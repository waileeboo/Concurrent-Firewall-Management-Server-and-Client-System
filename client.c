#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define BUFFERLENGTH 256

/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int sockfd, n;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;

    char buffer[BUFFERLENGTH];
    // add if argc<3 print error

    if (argc < 4)
    {
        printf("Illegal request\n");
        exit(EXIT_FAILURE);
    }

    switch (*argv[3])
    {
    case 'A':
        if (argc != 6)
        {
            fprintf(stderr, "%c should have exactly 6 argument \n", *argv[3]);
            exit(1);
        }
        break;
    case 'C':
        if (argc != 6)
        {
            fprintf(stderr, "%c should have exactly 6 argument \n", *argv[3]);
            exit(1);
        }
        break;
    case 'D':
        if (argc != 6)
        {
            fprintf(stderr, "%c should have exactly 6 argument \n", *argv[3]);
            exit(1);
        }
        break;
    case 'L':
        if (argc != 4)
        {
            fprintf(stderr, "%c should have exactly 4 argument \n", *argv[3]);
            exit(1);
        }
        break;
    default:
        fprintf(stderr, "Illegal Request\n");
        exit(1);
    }

    /* Obtain address(es) matching host/port */
    /* code taken from the manual page for getaddrinfo */

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0; /* Any protocol */

    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sockfd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);

        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break; /* Success */

        close(sockfd);
    }

    if (rp == NULL)
    { /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result); /* No longer needed */

    /* prepare message */
    int length = 0;
    for (int i = 3; i < argc; i++)
    {
        length += strlen(argv[i] + 1); // added +1
    }
    char *store;
    store = (char *)malloc(sizeof(char) * length + argc + 3);
    if (store == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    int tmp = 0;
    for (int i = 3; i < argc - 1; i++)
    {
        tmp += sprintf((store + tmp), "%s", (char *)(argv[i]));
        tmp += sprintf(store + tmp, " ");
    }
    tmp += sprintf((store + tmp), "%s", (char *)(argv[argc - 1]));

    /* send message */
    n = write(sockfd, store, strlen(store));
    if (n < 0)
        error("ERROR writing to socket");
    bzero(buffer, BUFFERLENGTH);
    free(store);

    /* wait for reply */
    n = read(sockfd, buffer, BUFFERLENGTH);
    if (n < 0)
        error("ERROR reading from socket");
    
    printf("%s\n", buffer);
    
    // fwrite(buffer, sizeof(char), n, stdout);
    // printf("\n");
    close(sockfd);
    return 0;
}
