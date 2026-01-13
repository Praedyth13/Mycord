#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <stdint.h>

typedef enum MessageType {
	LOGIN = 0, //OUTBOUND messages < 9
	LOGOUT = 1,
	MSG_SEND = 2,

	MSG_RCV = 10, //INBOUND messages > 9
	DSCNCT = 12,
	SYSTEM = 13,
} message_type_t;

typedef struct __attribute__((packed)) Message {
	message_type_t type;
	unsigned int time;
	char username[32];
	char message[1024];
} message_t;

typedef struct Settings {
    struct sockaddr_in server;
    bool quiet;
    int socket_fd;
    bool running;
    char username[32];
    const char* color;
} settings_t;

static const char* COLOR_RED = "\033[31m";
static const char* COLOR_GREEN = "\033[0;32m";
static const char* COLOR_BLUE = "\033[0;34m";
static const char* COLOR_YELLOW = "\033[1;33m";
static const char* COLOR_MAGENTA = "\033[0;35m";
static const char* COLOR_CYAN = "\033[0;36m";
static const char* COLOR_WHITE = "\033[1;37m";
static const char* COLOR_GRAY = "\033[90m";
static const char* COLOR_RESET = "\033[0m";
static settings_t settings = {0};

void logout(){
	settings_t* sp = &settings;
	message_t logout;
	logout.type = htonl(LOGOUT);

	while((write((*sp).socket_fd, &logout, sizeof(logout))) != sizeof(logout)){ //send logout message with only message type
		continue; //retry write
	}
	close((*sp).socket_fd); //close the socket
	(*sp).socket_fd = -1; //nullify fd
}

void print_error(char message[], int code){
	fprintf(stderr, "Error: %s\n", message); //print error message
	_exit(code); //exit with non-zero code
}

void print_help(){
        printf(
        "usage: ./client [-h] [--port PORT] [--ip IP] [--domain DOMAIN] [-c {RED,GREEN,BLUE,YELLOW,MAGENTA,CYAN,WHITE}] [--quiet]\n\n"

        "mycord client\n\n"

        "options:\n"
                "--help                show this help message and exit\n"
                "--port PORT           port to connect to (default: 8080)\n"
                "--ip IP               IP to connect to (default: '127.0.0.1')\n"
                "--domain DOMAIN       Domain name to connect to (if domain is specified, IP must not be)\n"
		"-c, --color {RED,GREEN,BLUE,YELLOW,MAGENTA,CYAN,WHITE}\n"
		"		       select @mention highlight color (default: RED)\n"
                "--quiet               do not perform alerts or mention highlighting\n\n"

        "examples:\n"
                "./client --help (prints the above message)\n"
                "./client --port 1738 (connects to a mycord server at 127.0.0.1:1738)\n"
                "./client --domain example.com (connects to a mycord server at example.com:8080)\n");
}

const char* get_color_code(char color_str[]){
	if(strncmp(color_str, "RED", 8) == 0){ //string compare the color argument to find the correct color code
		return COLOR_RED;
	}
	else if(strncmp(color_str, "GREEN", 8) == 0){
		return COLOR_GREEN;
	}
	else if(strncmp(color_str, "BLUE", 8) == 0){
                return COLOR_BLUE;
        }
	else if(strncmp(color_str, "YELLOW", 8) == 0){
                return COLOR_YELLOW;
        }
	else if(strncmp(color_str, "MAGENTA", 8) == 0){
                return COLOR_MAGENTA;
        }
	else if(strncmp(color_str, "CYAN", 8) == 0){
                return COLOR_CYAN;
        }
	else if(strncmp(color_str, "WHITE", 8) == 0){
                return COLOR_WHITE;
        }
	else{
		return COLOR_RESET; //if there is an error in the color argument, return reset to signal failure
	}
}

int process_args(int argc, char *argv[]) {
	settings_t* sp = &settings; //create reference pointer
	bool ip_given = false; //track if ip was given

	for(int i = 1; i < argc; i++){ //iterate through parsed arguments and execute accordingly, start at 1 to avoid checking the function name
		if(strncmp(argv[i], "-h", 8) == 0 || strncmp(argv[i], "--help", 8) == 0){
			print_help(); //run help function
			_exit(0); //exit when help function is run
		}

		else if(strncmp(argv[i], "--ip", 8) == 0){ //check for ip input
			if(argc <= (i+1)){
				print_error("Missing IP address", -1); //print the error message
			}

			if(inet_pton(AF_INET, argv[i+1], &(*sp).server.sin_addr) != 1){ //copy the given ip address
				print_error("Failure to resolve IP address", -6);
			}

			ip_given = true; //save that an ip was given
			i++; //increment to skip over ip
		}

		else if(strncmp(argv[i], "--domain", 8) == 0){ //check for domain input
			if(argc <= (i+1)){
				print_error("Missing domain name", -2);
			}

			else if(ip_given){ //exclude if given ip
				print_error("Cannot provide domain name when given IP", -10);
			}

			struct hostent* host_info = gethostbyname(argv[i+1]); //resolve host name
			if(host_info == NULL){
				print_error("Failure to resolve hostname", -7);
			}

			(*sp).server.sin_addr = *(struct in_addr*)host_info -> h_addr_list[0]; //copy the given domain name
			i++; //increment to skip over domain name
		}

		else if(strncmp(argv[i], "--port", 8) == 0){ //check port for ip
			if(argc <= (i+1)){
				print_error("Missing port number", -3);
			}

			(*sp).server.sin_port = htons(atoi(argv[i+1])); //copy the given port
			i++; //increment to skip over the port argument
		}

		else if(strncmp(argv[i], "--quiet", 8) == 0){ //check quiet
			(*sp).quiet = true; //suppress @ mentions
		}

		else if(strncmp(argv[i], "-c", 8) == 0 || (strncmp(argv[i], "--color", 8) == 0)){
			if(argc <= (i+1)){
				print_error("Missing color", -4);
			}

			if(((*sp).color = get_color_code(argv[i+1])) == COLOR_RESET ){ //copy the given color
				print_error("Unrecognized color code", -8);
			}

			i++; //increment to skip over the port argument
		}

		else{
			print_error("Unrecognized argument", -5);
		}
	}
}

int get_username(settings_t* sp) {
	char* username = getenv("USER"); //get char*
	if(username != NULL){
		strncpy((*sp).username, username, 31); //copy username into settings
		(*sp).username[31] = '\0'; //ensure null termination
	}

	else{
		print_error("Failure to read USER variable", -9);
	}
}

void handle_signal(int signal) {
	settings.running = false;
}

ssize_t perform_full_read(void *buf, size_t n) {
	settings_t* sp = &settings;
	size_t final = 0;

	while(final < n){
		ssize_t count = read((*sp).socket_fd, buf + final, n - final);

		if(count > 0){
			final += count;
		}

		else if(n == 0){
			return 0;
		}

		else{
			if(errno == EINTR){
				continue;
			}

			else if((*sp).running){
				print_error("Failed to read message", -16);
			}

			else{
				break; //if no longer running, break with no message
			}
		}

	}
	return final; //read full message
}

void highlight(message_t* mp){
	settings_t* sp = &settings;
	char text[9] = "@rck5368";
	char* cursor = (*mp).message; //set a pointer for the message
	const size_t length = strlen(text);

	while(cursor != NULL){ //iterate through the message and highlight any mentions
		char* match = strstr(cursor, text);
		if(match == NULL){
			fputs(cursor, stdout); //print remaining if there is no mention
			return;
		}

		fwrite(cursor, 1, match - cursor, stdout); //write the text before the mention

		fputs((*sp).color, stdout); //print the color
		fwrite(match, 1, length, stdout); //highlight the mention
		fputs(COLOR_RESET, stdout); //end highlighting

		cursor = match + length; //move cursor beyond match
	}

	return;
}

void* receive_messages_thread(void* arg) {
	settings_t* sp = &settings;
	int i = 0;
	message_t msg;

	while((*sp).running){ //while the connection is open
		perform_full_read(&msg, sizeof(msg)); //perform full read into msg
		if(!(*sp).running){ return 0;} //end the thread if no longer running
		msg.type = ntohl(msg.type); //network -> host conversion
		msg.time = ntohl(msg.time);

		struct tm* time_info; //timestamp creation
		char timestamp[50];
		time_t raw = (time_t)msg.time; //convert int to time
		time_info = localtime(&raw); //fill struct with corresponding local time info
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info); //format timestamp string

		if(msg.type < 9 || msg.type == 11 || msg.type > 13){ //ensure type is INBOUND
			print_error("Invalid Message Type", -17);
		}

		if(msg.type == MSG_RCV){
			printf("[%s] %s: ", timestamp, msg.username); //print the prefix
			if(!(*sp).quiet){
				highlight(&msg); //highlight/print the message
				fputc('\n', stdout);
			}

			else{
				printf("%s\n", msg.message); //print message without highlighting
			}
		}

		else if(msg.type == DSCNCT){
			printf("%s[DISCONNECT] %s%s\n", COLOR_RED, msg.message, COLOR_RESET); //disconnect message
			(*sp).running = false;
			close((*sp).socket_fd); //close socket
			(*sp).socket_fd = -1; //nullify fd, signal disconnected
		}

		else if(msg.type == SYSTEM){
			printf("%s%s: %s%s\n", COLOR_GRAY, msg.username, msg.message, COLOR_RESET); //gray highlight
		}
	}
	return 0;
}

int main(int argc, char *argv[]) {
	// setup sigactions (ill-advised to use signal for this project, use sigaction with default (0) flags instead)
	struct sigaction handler, old_action;
	memset(&handler, 0, sizeof(handler));
	handler.sa_handler = handle_signal;
	sigemptyset(&handler.sa_mask);
	sigaction(SIGINT, &handler, &old_action);
	sigaction(SIGTERM, &handler, &old_action);

	//initialize settings struct
	settings_t* sp = &settings;
	(*sp).quiet = false;
	(*sp).running = false;
	(*sp).color = COLOR_RED;

	//initilize settings.server
	inet_aton("127.0.0.1", &(*sp).server.sin_addr); //default to 127.0.0.1
	(*sp).server.sin_family = AF_INET; //set to IPv4
	(*sp).server.sin_port = htons(8080); //default to port 8080

	//parse arguments
	process_args(argc, argv); //call argument processor

	// get username
	get_username(sp); //acquire the username

	// create socket
	(*sp).socket_fd = socket(AF_INET, SOCK_STREAM, 0); //IPv4, TCP, default stream protocol
	if((*sp).socket_fd == -1){ //check fd
		print_error("Failure to create socket", -11);
	}

	// connect to server
	printf("Socket: %d\nIP: %d\nPort: %d\n", (*sp).socket_fd, (*sp).server.sin_addr, (*sp).server.sin_port);

	if((connect((*sp).socket_fd, (const struct sockaddr*) &(*sp).server, sizeof((*sp).server))) != 0){
		print_error("Failure to connect to server", -12);
	}

	(*sp).running = true; //track when the connection is running

	// create and send login message
	message_t login; //create login message struct
	login.type = htonl(LOGIN); //message type is LOGIN
	strncpy(login.username, (*sp).username, 32); //copy username

	if((write((*sp).socket_fd, &login, sizeof(login))) < sizeof(login)){ //send login message
		print_error("Failed to send login", -11);
	}

	// create and start receive messages thread
	pthread_t t1;
	pthread_create(&t1, NULL, receive_messages_thread, NULL); //create rcv_msg thread

	//create and send messages
	while((*sp).running){ //while the socket is open
		char line[1024]; //create char* to hold input
		int len = 0;
		while( (len = read(0, &line, 1023) ) != -1){
			line[1023] = '\0'; //ensure null termination
			line[len] = '\0'; //be extra sure
			bool skip = false;

			for(int i = 0; i < len; i++){ //iterate through line
				if(line[i] == '\n'){
					line[i] = '\0'; //remove newline characters
					len--; //decrease length by removed character
				}

				else if(line[i] == '\r'){
					line[i] = '\0'; //remove return characters
					len--; //decrease length by removed character
				}

				else if(!isprint((unsigned char)line[i])){ //check printability
					fprintf(stderr, "Error: Characters must be printable\n");
					skip = true;
					break;
				}
			}

			//err checking
                        if(len == 0){ //ensure non-empty message
                                fprintf(stderr, "Error: Message Empty\n");
                                skip = true;
                                continue;
                        }

                        else if(len < 1 || len > 1023){ //ensure message length between 1 and 1023
                                fprintf(stderr, "Error: Incorrect Message Length\n");
                                skip = true;
                                continue;
                        }

			if(skip){
				continue; //do not send the message
			}

			//construct message
			message_t send;
			send.type = htonl(MSG_SEND); //type is sent
			send.time = 0;
			strcpy(send.username, (*sp).username); //copy username
			strcpy(send.message, line); //copy message

			//send message
			if((write((*sp).socket_fd, &send, sizeof(send))) < sizeof(send)){ //send message
        			print_error("Failed to send message", -14);
        		}

		}
	}

	if((*sp).socket_fd != -1){ //do not send logout when disconnected
		logout();
	}

	//clean up & return
	void* retval;
	pthread_join(t1, &retval); //wait for thread return

	return 0;
}
