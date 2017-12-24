
#include <sys/select.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <errno.h>

#include <arpa/inet.h>
#include <signal.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <gtk/gtk.h>

#include <pthread.h>

#include "secure.h"



static void button_send(GtkWidget *widget, gpointer data);
static gboolean check_file(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, guint t, gpointer data);
static void get_file(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, GtkSelectionData *selection_data, guint info, guint t, gpointer data);

static void *run_gui(void * param);

static void show_gui(int *argc, char ** argv[]);

static void show_error(char * err);

enum
{
	FILE_ICON,
	PLAIN_TEXT,
	LIST_TEXT,
	COMPOUND_TEXT
};

static GtkTargetEntry target_list[] = 
{
	{"x-special/gnome-icon-list",	0,	FILE_ICON},
	{"text/plain",					0,	PLAIN_TEXT},
	{"text/uri-list",				0,	LIST_TEXT},
	{"COMPOUND_TEXT",				0,	COMPOUND_TEXT}
};

static guint n_targets = G_N_ELEMENTS(target_list);

static GtkWidget *label;
static GtkWidget *ip;

static char *gui_file;
static int gui_file_len;







struct letter
{
	unsigned char *ip;
	int iplen;
	unsigned char *fp;
	int fplen;
	unsigned char *msg;
	int msglen;
};

FILE *openfile(unsigned char *name, int namelen);
void free_letter(struct letter *l);

int process(struct letter *out, char *raw, int rawlen);
int sendletter(struct letter *l);
int receiveletter(int sfd);

void throwerror(unsigned char *err) {
	fprintf(stderr, "error! %s\n", err);
	exit(-1);
}

int main (int argc, char * argv[])
{

	show_gui(&argc, &argv);
	
	int i;
	
	fd_set read_set;
	FD_ZERO(&read_set);
	
	secure_init();
	
	printf("\n\n\t\t---------Welcome to CryptoMail---------\n\n");
	printf("To send a file, type the filename and the destination ip as below:\n  [test.txt] [some.destination.edu]\n");
	
	/*		set up server socket		*/

	struct sockaddr_in ssaddr;
	int port, ssfd;
	
	if ((ssfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		throwerror("Error opening server socket");
	
	memset((char *) &ssaddr, 0, sizeof(ssaddr));
	port = 4321;
	ssaddr.sin_addr.s_addr = INADDR_ANY;
	ssaddr.sin_port = htons(port);
	
	if (bind(ssfd, (struct sockaddr *) &ssaddr, sizeof(ssaddr)) < 0)
		throwerror("Error binding server socket");
	
	listen(ssfd, 5);

	FD_SET(0, &read_set);
	FD_SET(ssfd, &read_set);
	
	unsigned char buf[256];
	bzero(buf, 256);
	
	while (1)
	{
		if (select (FD_SETSIZE, &read_set, NULL, NULL, NULL) < 0) {
			throwerror("error with select");
		}
		
		for (i = 0; i < FD_SETSIZE; i++)
		{
			if (FD_ISSET(i, &read_set))
			{
				/*				input from terminal: [file] [ip]			*/
				if (i == 0)
				{
					struct letter l;
					int msglen = read(i, buf, 255);
					if (process(&l, buf, msglen)) {
						if (!sendletter(&l)) {
							printf("File could not be sent\n");
						} else {
							printf("File successfully sent\n");
						}
					}
					else {
						printf("Input couldn't be processed\nUse form [filename.ext] [ip]\n");
					}
					memset(buf, 0, 256);
					free_letter(&l);
				}
				/*				connection from a remote socket				*/
				if (i == ssfd) 
				{
					printf("accept... \n");
					show_error("Receiving a connection!");
					struct sockaddr_in saddr;
					socklen_t saddrlen = sizeof(saddr);
					int sfd, glen;
					if ((sfd = accept(ssfd, (struct sockaddr *) &saddr, &saddrlen)) < 0) {
						//error("Error accepting socket connection\n");
						show_error("Error accepting socket connection");
					}
					printf("Connected! sfd is %d\n", sfd);
					show_error("Connection made!");
					receiveletter(sfd);
				}
			}
		}
	}
	return 0;
}

void free_letter(struct letter *l) 
{
	if (!l)
		return;
	if (*(l->ip))
		free(l->ip);
	if (*(l->fp))
		free(l->fp);
	if (*(l->msg))
		free(l->msg);
}

int process(struct letter *out, char *raw, int rawlen)
{
	int i;
	int word = 0;
	int lastword = 0;
	
	unsigned char *fp;
	int fplen;
	unsigned char *ip;
	int iplen;
	unsigned char *msg;
	int msglen;
	
	for (i = 0; i < rawlen; i++) {
		if (raw[i] == ' ' || raw[i] == '\n' || raw[i] == '\0') {
			switch (word) {
				case 0:			//set the file name and length
					fplen = i - lastword;
					fp = malloc(fplen);
					raw[i] = '\0';
					memcpy((char *) fp, (unsigned char *) raw, fplen);
					lastword = i+1;
					word++;
					break;
				case 1:			//set the ip and ip length
					iplen = i - lastword;
					ip = malloc(iplen);
					raw[i] = '\0';
					memcpy((char *) ip, (unsigned char *) &raw[lastword], iplen);
					lastword = i+1;
					word++;
					break;
			}
		}
	}
	
	ip[iplen] = '\0';
	fp[fplen] = '\0';
	
	out->fp = fp;
	out->fplen = fplen;
	
	out->ip = ip;
	out->iplen = iplen;
	
	if (!(fp || ip))
		return 0;
	
	/*				open file and retrieve contents				*/
	FILE *file;
	
	if (!(file = fopen(fp, "r")))
		return 0;
	
	msglen = 0;
	
	char buf[2048];
	
	msglen += fread(buf, sizeof(char), 2048, file);
	
	if (!msglen) {
		printf("File could not be read\n");
		show_error("File could not be read");
		return 0;
	}
	
	if (msglen == 2048) {
		printf("File is too large; must be less than 2048 bytes\n");
		show_error("File is too large; must be less than 2048 bytes");
		return 0;
	}
	
	fclose(file);
	
	msg = malloc(sizeof(char) * (msglen + 1));
	memcpy((char *) msg, (unsigned char *) buf, msglen);
	msg[msglen] = '\0';
	
	out->msg = msg;
	out->msglen = msglen;
	
	if (!msg)
		return 0;
	
	return 1;
}

//note - vulnerable to lost connection, indefinite blocking, etc.
int sendletter(struct letter *l)
{
	//socket vars
	int port, sfd;
	struct sockaddr_in saddr;
	struct hostent *server;
	port = 4321;
	
	//message (stack) vars
	char pubkey[512];
	int pubkeylen;
	int i;
	char buf[4];
	int buflen;
	
	char plain[2048 + 512 + 4];
	int plainlen = l->fplen + l->msglen + 4;
	
	char enc[2048 + 512 + 4];
	int enclen;
	
	//encryption allocated (heap) vars
	unsigned char *ek;
	int ekl;
	unsigned char *iv;
	int ivl;
	
	printf("Sending file \"%s\"...\n", l->fp);
	show_error("Sending file");
	
	if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("Network error\n");
		show_error("Network error");
		return 0;
	}
	if (!(server = gethostbyname(l->ip))) {
		printf("Network error\n");
		show_error("Network error");
		return 0;
	}
	memset((char *) &saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	memcpy((char *) &saddr.sin_addr.s_addr, (char *) server->h_addr, server->h_length);
	saddr.sin_port = htons(port);
	if (connect(sfd, (struct sockaddr *) & saddr, sizeof(saddr)) < 0) {
		printf("Invalid or inactive IP; program must be running at remote ip\n");
		show_error("Invalid or inactive IP; program must be running at remote ip");
		return 0;
	}
	
	/*				receive their pub key				*/
	pubkeylen = read(sfd, pubkey, sizeof(char)*512);
	
	/*				encrypt the message					*/
	
	memset(buf, 0, 4);
	buflen = sprintf(buf, "%d", l->fplen);
	for (i = 4; i > buflen; i--) {
		buf[i-1] = '.';
	}
	memcpy(plain, buf, 4);
	memcpy((char *) &plain[4], (char *) l->fp, l->fplen);
	memcpy((char *) &plain[l->fplen+4], (char *) l->msg, l->msglen);
	
	encrypt(plain, plainlen, enc, &enclen, pubkey, pubkeylen, &ek, &ekl, &iv, &ivl);	//encrypt it
	
	/*				write metadata					*/
	//ek, ekl
	memset(buf, 0, 4);
	buflen = sprintf(buf, "%d", ekl);
	for (i = 4; i > buflen; i--) {
		buf[i-1] = '\0';
	}
	write(sfd, buf, 4);
	write(sfd, ek, ekl);
	
	//iv, ivlen
	memset(buf, 0, 4);
	buflen = sprintf(buf, "%d", ivl);
	for (i = 4; i > buflen; i--) {
		buf[i-1] = '\0';
	}
	write(sfd, buf, 4);
	write(sfd, iv, ivl);
	
	/*					write combined				*/
	memset(buf, 0, 4);
	buflen = sprintf(buf, "%d", enclen);
	for (i = 4; i > buflen; i--) {
		buf[i-1] = '\0';
	}
	write(sfd, buf, 4);
	write(sfd, enc, enclen);
	
	/*					cleanup						*/
	close(sfd);
	secure_cleanup(ek, iv);
	
	return 1;
}

//vulnerable to any variations in communication protocol and network disruptions
int receiveletter(int sfd) 
{	
	unsigned char buf[4];
	int buflen;
	
	unsigned char fp[512];
	int fplen;
	
	unsigned char msg[2048];
	int msglen;
	
	char enc[2048 + 512 + 4];
	int enclen;
	
	unsigned char ek[512];
	int ekl;
	unsigned char iv[32];
	int ivl;
	
	//heap vars
	unsigned char *pubkey = NULL;
	int pubkeylen;
	
	FILE *file;
	
	printf("\t\tReceiving a file!\n");
	show_error("Receiving a file!");


    printf("Show error works fine\n");
	
	/*				send my pub key				*/
	pubkeylen = loadKey(&pubkey, 0);		//not guaranteed to work; should have error checking
	printf("loadKey works\n");
    write(sfd, pubkey, pubkeylen);
    printf("writing works\n");
	OPENSSL_free(pubkey);
	printf("Freeing works\n");
	printf("temp\n");
	
	/*				get metadata					*/
	//ek
	memset(ek, 0, 512);
	read(sfd, buf, sizeof(char)*4);
	ekl = strtol(buf, 0, 10);
	read(sfd, ek, ekl);
	if (ekl < 512)
		ek[ekl] = '\0';
	
	//iv
	memset(iv, 0, 32);
	memset(buf, 0, 4);
	read(sfd, buf, sizeof(char)*4);
	ivl = strtol(buf, 0, 10);
	//printf("ivlen: %d\n", ivl);
	read(sfd, iv, ivl);
	if (ivl < 32)
		iv[ivl] = '\0';
	
	/*				receive msg						*/
	memset(enc, 0, 32);
	memset(buf, 0, 4);
	read(sfd, buf, sizeof(char)*4);
	enclen = strtol(buf, 0, 10);
	if (msglen > (2048 + 512 + 4)) {
		throwerror("Received message is too long");
	}
	read(sfd, enc, enclen);
	if (enclen < (32))
		enc[enclen] = '\0';
	
	/*				decrypt msg						*/
	if((msglen = decrypt(msg, enc, enclen, ek, ekl, iv)) < 0) {
		printf("File could not be decrypted\n");
		show_error("File could not be decrypted");
		close(sfd);
		return 0;
	}
	
	memset(buf, 0, 4);
	memcpy(buf, msg, 4);
	fplen = strtol(buf, 0, 10);
	if (fplen < 512)
		memcpy(fp, &msg[4], fplen);
	else {
		printf("File name is too large\n");
		show_error("File name is too large");
		close(sfd);
		return 0;
	}
	
	fp[fplen] = '\0';
	
	printf("File successfully received and decrypted!\nThe File name is \"%s\"\n", fp);
	show_error("File successfully received and decrypted!");
	
	/*				write to a file					*/
	if(!(file = openfile(fp, fplen))) {
		printf("File could not be saved! The Data is lost\n");
		show_error("File could not be saved! The Data is lost");
		close(sfd);
		return 0;
	}
	fwrite(&msg[fplen+4], msglen - (fplen + 4), 1, file);
	
	printf("The decrypted file is now saved in this directory\n");
	show_error("The decrypted file is now saved in this directory");
	
	/*					cleanup						*/
	fclose(file);
	close(sfd);
	
	return 1;
}

FILE *openfile(unsigned char *name, int namelen)
{
	FILE *fp = NULL;
	unsigned char *newname = NULL;
	int c = 0;
	
	while ((fp = fopen(name, "r")))
	{
		if (c > 9) {
			printf("An alternate name could not be made\n");
			show_error("An alternate name could not be made");
			return 0;
		}
		if (newname) {
			c++;
			name[1] = c + '0';
		} else {
			printf("A file of the same name already exists; trying to create an alternate name\n");
			show_error("A file of the same name already exists; trying to create an alternate name");
			c++;
			newname = malloc(sizeof(char) * (namelen + 4));
			memcpy(newname, name, namelen);
            
            unsigned char *split = strstr(name, ".");
            int diff = split - name;

            for (int i = diff; i < namelen+3; i++) {
                newname[i+3] = name[i];
            }

            newname[diff] = '(';
            newname[diff+1] = c + '0';
            newname[diff+2] = ')';

			name = newname;
		}
		fclose(fp);
	}
	if (!(fp = fopen(name, "w"))) {
		printf("The file can't be written\n");
		show_error("The file can't be written");
		return 0;
	}
	if (newname)
		free(newname);
	return fp;
}







static void show_gui(int *argc, char ** argv[])
{
	GtkWidget *window;
    GtkWidget *drag;
    GtkWidget *button;
    GtkWidget *box;
    GtkWidget *box_lower;
    GtkWidget *box_text;
    
    gtk_init(argc, argv);
    
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "crypto");
    gtk_window_set_default_size (GTK_WINDOW(window), 300, 175);
    g_signal_connect(window, "delete-event", G_CALLBACK(gtk_main_quit), NULL);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

	box = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(window), box);
    
    
    /*						destination setup  						*/
	
    drag = gtk_button_new_with_label("Drag file here");
    
    gtk_drag_dest_set(drag, GTK_DEST_DEFAULT_MOTION | GTK_DEST_DEFAULT_HIGHLIGHT | GTK_DEST_DEFAULT_DROP | GTK_DEST_DEFAULT_ALL, target_list, n_targets, GDK_ACTION_DEFAULT | GDK_ACTION_COPY);
    
    /*						data drop attempted						*/
    
    g_signal_connect(drag, "drag_drop", G_CALLBACK(check_file), NULL);
    
    /*							get data							*/
    
    g_signal_connect(drag, "drag_data_received", G_CALLBACK(get_file), NULL);
    
    gtk_box_pack_start(GTK_BOX(box), drag, TRUE, TRUE, 0);
    
    
    
    /*				-------Lower controls-------  					*/
    
    box_lower = gtk_hbox_new(FALSE, 0);
    
    box_text = gtk_vbox_new(FALSE, 0);
    
    /*							ip		  							*/
    ip = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(ip), "Enter ip here");
    gtk_box_pack_start(GTK_BOX(box_text), ip, TRUE, TRUE, 0);
    
    /*							label			  					*/
    label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(box_text), label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box_lower), box_text, TRUE, TRUE, 0);
    
   	/*							button			  					*/
    button = gtk_button_new_with_label("Send");
    g_signal_connect(button, "clicked", G_CALLBACK(button_send), (gpointer) "button 1");
    gtk_box_pack_start(GTK_BOX(box_lower), button, TRUE, TRUE, 0);
    
   	gtk_box_pack_start(GTK_BOX(box), box_lower, TRUE, TRUE, 0);
   	
   	gtk_widget_show(label);
   	gtk_widget_show(ip);
   	gtk_widget_show(box_text);
    gtk_widget_show(box_lower);
    gtk_widget_show(drag);
    gtk_widget_show(button);
    gtk_widget_show(box);
    
    gtk_widget_show(window);
    
    pthread_t thread;
    
    pthread_create(&thread, NULL, &run_gui, NULL);
    
}


void *run_gui(void * param)
{
	gtk_main();
}

static gboolean check_file(GtkWidget *widget, GdkDragContext *context, gint x, gint y, guint t, gpointer user_data)
{
	gboolean is_valid;
	GdkAtom target_type;
	GList * targets;
	
	if ((targets = gdk_drag_context_list_targets(context))) {
		
		gpointer target;
		
		target_type = GDK_POINTER_TO_ATOM 
			(g_list_nth_data 
				(gdk_drag_context_list_targets 
					(context), 
					FILE_ICON));
		return TRUE;
	}
	return FALSE;
}

void get_file(GtkWidget *widget, GdkDragContext *dc, gint x, gint y, GtkSelectionData *selection_data, guint info, guint t, gpointer user_data)
{
	gboolean success = FALSE;
	gchar *msg;
	gint size;
	
	if (gui_file)
		free(gui_file);
	
	gui_file = malloc(256);
	
	
	if ((selection_data != NULL) && ((size = gtk_selection_data_get_length (selection_data)) >= 0)) {
		
		msg = (gchar*) gtk_selection_data_get_data(selection_data);
		
		int i;
		int slashes = 0;
		int start_str = 7;
		int end_str = -1;
		for (i = 0; i < size; i++) {
			if (msg[i] == 13) {
				end_str = i;
				break;
			}
		}
		
		
		for (i = start_str; i < end_str; i++) {
			gui_file[i-7] = (char) msg[i];
		}
		
		gui_file_len = end_str - start_str;
	}
	
	
	
	gtk_drag_finish (dc, success, FALSE, t);
}

static void button_send(GtkWidget *widget, gpointer data)
{
	struct letter l;
	guint16 iplen;
	char buf[256];
	int i;
	
	if (!gui_file) {
		show_error("Drag a file to the gui first");
		return;
	}
	
	for (i = 0; i < gui_file_len; i++) {
		buf[i] = gui_file[i];
	}
	
	buf[gui_file_len] = ' ';
	
	printf("buf: %s\n", buf);
	iplen = gtk_entry_get_text_length(GTK_ENTRY (ip));
	const gchar *msg = gtk_entry_get_text(GTK_ENTRY (ip));
	if (iplen == 0) {
		show_error("Enter a valid ip first");
		return;
	}
	
	
	for (i = 0; i < iplen; i++) {
		buf[i+gui_file_len+1] = msg[i];
	}
	
	buf[i+gui_file_len+2] = '\0';
	
	if (process(&l, buf, iplen+gui_file_len+3)) {
		if (!sendletter(&l)) {
			show_error("File could not be sent");
		} else {
			show_error("File successfully sent");
		}
	}
	else {
		show_error("Input couldn't be processed\nUse form [filename.ext] [ip]");
	}
	
	free_letter(&l);
}

static void show_error(char * err)
{
	gtk_label_set_text(GTK_LABEL (label), err);
}
