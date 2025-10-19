/* A threaded server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#define BUFFERLENGTH 256

#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// add new struct
struct queryRules_t
{
    int ipaddr1[4];
    int port1;
    struct queryRules_t *next;
};

struct firewallRule_t
{
    int ipaddr1[4];
    int ipaddr2[4];
    int port1;
    int port2;
    struct queryRules_t *quries;
};

struct firewallRules_t
{
    struct firewallRule_t *rule;
    struct firewallRules_t *next;
};

struct ruleErrors_t
{
    char *line;
    struct ruleErrors_t *next;
};

// code from assignment 1 checkpacket start here

struct firewallRules_t *addRule(struct firewallRules_t *rules, struct firewallRule_t *rule)
{
    struct firewallRules_t *newRule;

    newRule = malloc(sizeof(struct firewallRules_t));
    newRule->rule = rule;
    newRule->next = rules;
    return newRule;
}

int compareIPAddresses(int *ipaddr1, int *ipaddr2)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (ipaddr1[i] > ipaddr2[i])
        {
            return 1;
        }
        else if (ipaddr1[i] < ipaddr2[i])
        {
            return -1;
        }
    }
    return 0;
}

char *parseIPaddress(int *ipaddr, char *text, bool checkFile)
{
    char *oldPos, *newPos;
    long int addr;
    int i;

    oldPos = text;
    for (i = 0; i < 4; i++)
    {
        if (oldPos == NULL || *oldPos < '0' || *oldPos > '9')
        {
            return NULL;
        }

        addr = strtol(oldPos, &newPos, 10);
        if (newPos == oldPos)
        {
            return NULL;
        }
        if ((addr < 0) || addr > 255)
        {
            ipaddr[0] = -1;
            return NULL;
        }
        if (i < 3)
        {
            if ((newPos == NULL) || (*newPos != '.'))
            {
                ipaddr[0] = -1;
                return NULL;
            }
            else
                newPos++;
        }
        else if ((newPos == NULL) || ((*newPos != ' ') && (*newPos != '-') && checkFile) || (!checkFile && (*newPos != '\0')))
        {
            ipaddr[0] = -1;
            return NULL;
        }
        ipaddr[i] = addr;
        oldPos = newPos;
    }
    return newPos;
}

char *parsePort(int *port, char *text)
{
    char *newPos;

    if ((text == NULL) || (*text < '0') || (*text > '9'))
    {
        return NULL;
    }
    *port = strtol(text, &newPos, 10);
    if (newPos == text)
    {
        *port = -1;
        return NULL;
    }
    if ((*port < 0) || (*port > 65535))
    {
        *port = -1;
        return NULL;
    }
    return newPos;
}

void printIPaddress(int *ipaddr)
{
    printf("%d.%d.%d.%d", ipaddr[0],
           ipaddr[1],
           ipaddr[2],
           ipaddr[3]);
}

bool checkIPAddress(int *ipaddr1, int *ipaddr2, int *ipaddr)
{
    int res;

    res = compareIPAddresses(ipaddr, ipaddr1);
    if (compareIPAddresses(ipaddr, ipaddr1) == 0)
    {
        return true;
    }
    else if (ipaddr2[0] == -1)
    {
        return false;
    }
    else if (res == -1)
    {
        return false;
    }
    else if (compareIPAddresses(ipaddr, ipaddr2) <= 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int checkPort(int port1, int port2, int port)
{
    if (port == port1)
    {
        return 0;
    }
    else if (port < port1)
    {
        return -1;
    }
    else if (port2 == -1 || port > port2)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void printRule(struct firewallRule_t *rule)
{
    printf("Rule: %d.%d.%d.%d", rule->ipaddr1[0],
           rule->ipaddr1[1],
           rule->ipaddr1[2],
           rule->ipaddr1[3]);
    if (rule->ipaddr2[0] != -1)
    {
        printf("-");
        printIPaddress(rule->ipaddr2);
    }
    printf(" %d", rule->port1);
    if (rule->port2 != -1)
    {
        printf("-");
        printf("%d", rule->port2);
    }
    printf("\n");
}

int compareRules(const void *arg1, const void *arg2)
{
    struct firewallRules_t *rule1, *rule2;

    rule1 = *((struct firewallRules_t **)arg1);
    rule2 = *((struct firewallRules_t **)arg2);
    if (rule1->rule->port1 < rule2->rule->port1)
    {
        return -1;
    }
    else if (rule1->rule->port1 > rule2->rule->port1)
    {
        return 1;
    }
    else
        return (compareIPAddresses(rule1->rule->ipaddr1, rule2->rule->ipaddr1));
}

struct firewallRules_t *sortRules(struct firewallRules_t *rules, int noOfRules)
{
    struct firewallRules_t **allRules, **tmp, *sortedRules;
    int i;

    /* empty list is already sorted; rest of the function assumes noOfRules > 0 */
    if (noOfRules == 0)
    {
        return NULL;
    }

    allRules = malloc(sizeof(struct firewallRules_t *) * noOfRules);
    tmp = allRules;
    while (rules)
    {
        *tmp = rules;
        tmp++;
        rules = rules->next;
    }
    qsort(allRules, noOfRules, sizeof(struct firewallRules_t *), compareRules);

    for (i = 0; i < noOfRules - 1; i++)
    {
        allRules[i]->next = allRules[i + 1];
    }
    allRules[noOfRules - 1]->next = NULL;

    sortedRules = allRules[0];
    free(allRules);
    return sortedRules;
}

struct firewallRule_t *readRule(char *line)
{
    struct firewallRule_t *newRule = NULL;
    char *pos;

    // parse IP addresses
    newRule = malloc(sizeof(struct firewallRule_t));
    pos = parseIPaddress(newRule->ipaddr1, line, true);
    if ((pos == NULL) || (newRule->ipaddr1[0] == -1))
    {
        free(newRule);
        return NULL;
    }
    if (*pos == '-')
    {
        // read second IP address
        pos = parseIPaddress(newRule->ipaddr2, pos + 1, true);
        if ((pos == NULL) || (newRule->ipaddr2[0] == -1))
        {
            free(newRule);
            return NULL;
        }

        if (compareIPAddresses(newRule->ipaddr1, newRule->ipaddr2) != -1)
        {
            free(newRule);
            return NULL;
        }
    }
    else
    {
        newRule->ipaddr2[0] = -1;
    }
    if (*pos != ' ')
    {
        free(newRule);
        return NULL;
    }
    else
        pos++;

    // parse ports
    pos = parsePort(&(newRule->port1), pos);
    if ((pos == NULL) || (newRule->port1 == -1))
    {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0'))
    {
        newRule->port2 = -1;
        return newRule;
    }
    if (*pos != '-')
    {
        free(newRule);
        return NULL;
    }

    pos++;
    pos = parsePort(&(newRule->port2), pos);
    if ((pos == NULL) || (newRule->port2 == -1))
    {
        free(newRule);
        return NULL;
    }
    if (newRule->port2 <= newRule->port1)
    {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0'))
    {
        return newRule;
    }
    free(newRule);
    return NULL;
}

struct ruleErrors_t *allErrors = NULL;

struct ruleErrors_t *addErrorRule(struct ruleErrors_t *errors, char *line)
{
    struct ruleErrors_t *newError;

    newError = malloc(sizeof(struct ruleErrors_t));
    newError->line = line;
    newError->next = errors;
    return newError;
}
// ennd of part 1 code
// assignement 2 start here
/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(1);
};

struct threadArgs_t
{
    int newsockfd;
    int threadIndex;
};

int isExecuted = 0;
int returnValue = 0;                             /* not used; need something to keep compiler happy */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for processing */

/* this is only necessary for proper termination of threads - you should not need to access this part in your code */
struct threadInfo_t
{
    pthread_t pthreadInfo;
    pthread_attr_t attributes;
    int status;
};
struct threadInfo_t *serverThreads = NULL;
int noOfThreads = 0;
pthread_rwlock_t threadLock = PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t threadCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t threadEndLock = PTHREAD_MUTEX_INITIALIZER;

struct firewallRules_t *allRules = NULL;
pthread_rwlock_t locklinklist = PTHREAD_RWLOCK_INITIALIZER;

// pthread_rwlock_rdlock(&locklinklist);
// pthread_rwlock_unlock(&locklinklist);
//
// pthread_rwlock_wrlock(&locklinklist);
// pthread_rwlock_unlock(&locklinklist);

/* For each connection, this function is called in a separate thread. You need to modify this function. */
void *processRequest(void *args)
{
    struct threadArgs_t *threadArgs;
    char buffer[BUFFERLENGTH];
    int n;
    int tmp;

    threadArgs = (struct threadArgs_t *)args;
    bzero(buffer, BUFFERLENGTH);
    n = read(threadArgs->newsockfd, buffer, BUFFERLENGTH - 1);
    if (n < 0)
        error("ERROR reading from socket");

    // mycode
    printf("Here is the message: %s\n", buffer);
    if (buffer[0] == 'A')
    {
        struct firewallRule_t *newRule;
        newRule = readRule(&(buffer[2]));
        if (newRule == NULL)
        {
            char *msg = "Invalid rule";
            write(threadArgs->newsockfd, msg, strlen(msg));
            return NULL;
        }
        else
        {
            pthread_rwlock_wrlock(&locklinklist);

            bool same = false;
            struct firewallRules_t *newpoint = allRules;

            while (newpoint)
            {
                if (compareIPAddresses(newpoint->rule->ipaddr1, newRule->ipaddr1) == 0 &&
                    compareIPAddresses(newpoint->rule->ipaddr2, newRule->ipaddr2) == 0 &&
                    newpoint->rule->port1 == newRule->port1 &&
                    newpoint->rule->port2 == newRule->port2)
                {
                    same = true;
                    break;
                }
                newpoint = newpoint->next;
            }

            if (!same)
            {
                struct firewallRules_t *newNode = malloc(sizeof(struct firewallRules_t));
                if (newNode == NULL)
                {
                    
                    char *errorMsg = "Memory allocation Failed\n";
                    write(threadArgs->newsockfd, errorMsg, strlen(errorMsg));
                    pthread_rwlock_unlock(&locklinklist);
                    return NULL;
                }
                else
                {
                    newRule->quries = NULL;
                    newNode->rule = newRule;
                    newNode->next = allRules;
                    allRules = newNode;
                    char *ruleAccepted = "Rule added";
                    write(threadArgs->newsockfd, ruleAccepted, strlen(ruleAccepted));
                    pthread_rwlock_unlock(&locklinklist);
                    return (void *)allRules;
                }
            }
            else
            {

                char *errorMsg = "Rule added";
                write(threadArgs->newsockfd, errorMsg, strlen(errorMsg));
                free(newRule); // free new rule if already covered
                pthread_rwlock_unlock(&locklinklist);
                return NULL;
            }
        }
    }
    else if (buffer[0] == 'C')
    {
        struct firewallRule_t *checkRule;
        checkRule = readRule(&(buffer[2]));
        if (checkRule == NULL) {
            char *msg = "Illegal IP address or port specified";
            write(threadArgs->newsockfd, msg, strlen(msg));
            free(checkRule); // free checkRule
            return NULL;
        }
        else if (  checkRule->ipaddr2[0] != -1 && checkRule->port2 != -1)
        {
            char *msg = "Illegal IP address or port specified";
            write(threadArgs->newsockfd, msg, strlen(msg));
            free(checkRule); // free checkRule
            return NULL;
        }
        else
        {
            pthread_rwlock_wrlock(&locklinklist);

            bool range = false;
            struct firewallRules_t *newpoint = allRules;
            while (newpoint) // should i add ->next
            {
                // check if in range
                if (newpoint->rule->ipaddr2[0] == -1 && compareIPAddresses(newpoint->rule->ipaddr1, checkRule->ipaddr1) == 0 && newpoint->rule->port1 == checkRule->port1) // check if the IP have 1 or range IP
                {
                    range = true;
                    // pthread_rwlock_unlock(&locklinklist);
                    break;
                }
                else if (newpoint->rule->ipaddr2[0] != -1 && compareIPAddresses(newpoint->rule->ipaddr1, checkRule->ipaddr1) <= 0 &&
                         compareIPAddresses(newpoint->rule->ipaddr2, checkRule->ipaddr1) >= 0 &&
                         newpoint->rule->port1 <= checkRule->port1 && newpoint->rule->port2 >= checkRule->port1)
                {

                    range = true;
                    // pthread_rwlock_unlock(&locklinklist);
                    break;
                }

                newpoint = newpoint->next;
            }
            if (!range)
            {
                char *connectionreject = "Connection Rejected\n";
                write(threadArgs->newsockfd, connectionreject, strlen(connectionreject) + 1);
                free(checkRule); // free checkRule
                pthread_rwlock_unlock(&locklinklist);
                return NULL; // not return NULL??s
            }
            else
            {
                // pthread_rwlock_unlock(&locklinklist);
                // pthread_rwlock_wrlock(&locklinklist);

                char *connectionacpt = "Connection Accepted\n";
                write(threadArgs->newsockfd, connectionacpt, strlen(connectionacpt) + 1);
                struct queryRules_t *newAssoc;
                newAssoc = malloc(sizeof(struct queryRules_t));

                if (newAssoc == NULL)
                {
                    fprintf(stderr, "Insufficient memory to recored accepted packet");
                    pthread_rwlock_unlock(&locklinklist);
                    free(checkRule); // free checkRule
                    return NULL;
                }
                else
                {

                    // Add packet details to newAssoc heres
                    newAssoc->next = NULL;
                    memcpy(newAssoc->ipaddr1, checkRule->ipaddr1, sizeof(checkRule->ipaddr1));
                    // newAssoc->ipaddr1=checkRule->ipaddr1;
                    newAssoc->port1 = checkRule->port1;

                    struct queryRules_t *tmp = newpoint->rule->quries;

                    if (!tmp)
                    { // if no existing queries
                        tmp = newAssoc;
                        newAssoc->next = NULL;
                        newpoint->rule->quries = newAssoc;
                        pthread_rwlock_unlock(&locklinklist);
                        free(checkRule); // free checkRule
                        return newAssoc;
                    }

                    while (tmp->next)
                    {
                        tmp = tmp->next;
                    }

                    tmp->next = newAssoc;
                    newAssoc->next = NULL;
                    memcpy(newAssoc->ipaddr1, checkRule->ipaddr1, sizeof(checkRule->ipaddr1));
                    newAssoc->port1 = checkRule->port1;
                    free(checkRule); // free checkRule
                    pthread_rwlock_unlock(&locklinklist);
                    return newAssoc;
                }
            }
        }
    }

    if (buffer[0] == 'D')
    {
        struct firewallRule_t *newRule;
        newRule = readRule(&(buffer[2]));
        if (newRule == NULL)
        {
            char *msg = "Rule invalid";
            write(threadArgs->newsockfd, msg, strlen(msg));
            free(newRule); // free newRule
            return NULL;
        }
        else
        {
            pthread_rwlock_wrlock(&locklinklist);

            bool same = false;
            struct firewallRules_t *newpoint = allRules;
            struct firewallRules_t *prev = NULL;

            while (newpoint->next){
                if (compareIPAddresses(newpoint->rule->ipaddr1, newRule->ipaddr1) == 0 &&
                    (compareIPAddresses(newpoint->rule->ipaddr2, newRule->ipaddr2) == 0 || newpoint->rule->ipaddr2[0] == newRule->ipaddr2[0]) &&
                    newpoint->rule->port1 == newRule->port1 &&
                    newpoint->rule->port2 == newRule->port2)
                {
                    same = true;
                    break;
                }
                prev = newpoint;
                newpoint = newpoint->next;
            }

            if (compareIPAddresses(newpoint->rule->ipaddr1, newRule->ipaddr1) == 0 &&
                (compareIPAddresses(newpoint->rule->ipaddr2, newRule->ipaddr2) == 0 || newpoint->rule->ipaddr2[0] == newRule->ipaddr2[0]) &&
                newpoint->rule->port1 == newRule->port1 &&
                newpoint->rule->port2 == newRule->port2)
            {
                same = true;
            }

            if (same == true)
            {
                if (prev != NULL)
                {
                    prev->next = newpoint->next;
                }
                else
                {
                    allRules = newpoint->next;
                }
                struct queryRules_t *query = newpoint->rule->quries;
                while (query != NULL)
                {
                    struct queryRules_t *temp = query;
                    query = query->next;
                    free(temp);
                }
                free(newpoint->rule);
                free(newpoint);
                free(newRule);
                char *ruledelete = "Rule deleted";
                write(threadArgs->newsockfd, ruledelete, strlen(ruledelete));
                pthread_rwlock_unlock(&locklinklist);
                return (void *)allRules;
            }
            else
            {
                char *errorMsg = "Rule not found";
                free(newRule);
                write(threadArgs->newsockfd, errorMsg, strlen(errorMsg));
                pthread_rwlock_unlock(&locklinklist);
                return NULL;
            }
        }
    }
    else if (buffer[0] == 'L')
    {
        pthread_rwlock_rdlock(&locklinklist);
        struct firewallRules_t *tmp = allRules;
        int lenlist = 999;
        char *ruleString = malloc(lenlist * sizeof(char)); // should i do this ??
        if (ruleString == NULL)
        {
            char *errorMsg = "Memory allocation Failed\n";
            write(threadArgs->newsockfd, errorMsg, strlen(errorMsg));
            pthread_rwlock_unlock(&locklinklist);
            return NULL;
        }
        else
        {
            memset(ruleString, 0, lenlist);
            char *current = ruleString; // should i also do this?
            // list code
            int spaces = BUFFERLENGTH;

            while (tmp && spaces > 0)
            {
                int written = 0;
                if (spaces > 0)
                {
                    if (tmp->rule->port2 == -1)
                    {
                        written = snprintf(current, spaces,
                                           "Rule: %d.%d.%d.%d %d\n",
                                           tmp->rule->ipaddr1[0],
                                           tmp->rule->ipaddr1[1],
                                           tmp->rule->ipaddr1[2],
                                           tmp->rule->ipaddr1[3],
                                           tmp->rule->port1);
                    }
                    else
                    {
                        written = snprintf(current, spaces, "Rule: %d.%d.%d.%d-%d.%d.%d.%d %d-%d\n",
                                           tmp->rule->ipaddr1[0], tmp->rule->ipaddr1[1],
                                           tmp->rule->ipaddr1[2], tmp->rule->ipaddr1[3],
                                           tmp->rule->ipaddr2[0], tmp->rule->ipaddr2[1],
                                           tmp->rule->ipaddr2[2], tmp->rule->ipaddr2[3],
                                           tmp->rule->port1, tmp->rule->port2);
                    }
                    if (written < 0 || written >= spaces)
                    {
                        char *toomuchMsg = "I forgot\n";
                        write(threadArgs->newsockfd, toomuchMsg, strlen(toomuchMsg));
                        pthread_rwlock_unlock(&locklinklist);
                        return NULL;
                    }

                    if (written > 0)
                    {
                        current += written;
                        spaces -= written;
                    }
                }
                struct queryRules_t *tmpquery = tmp->rule->quries;

                while (tmpquery && spaces > 0)
                {
                    written = snprintf(current, spaces, "Query: %d.%d.%d.%d %d\n",
                                       tmpquery->ipaddr1[0],
                                       tmpquery->ipaddr1[1],
                                       tmpquery->ipaddr1[2],
                                       tmpquery->ipaddr1[3],
                                       tmpquery->port1);

                    if (written > 0)
                    {
                        current += written;
                        spaces -= written;
                    }
                    tmpquery = tmpquery->next;
                }
                tmp = tmp->next;
            }

            // end list code
            if (strlen(ruleString) == 0)
            {
                strcpy(ruleString, "No rules to display");
            }
            write(threadArgs->newsockfd, ruleString, strlen(ruleString));
            pthread_rwlock_unlock(&locklinklist);
            free(ruleString);
            return NULL;
        }
    }
    else
    {
        char *errorMsg = "Invalid Command\n";
        write(threadArgs->newsockfd, errorMsg, strlen(errorMsg));
        pthread_rwlock_unlock(&locklinklist);

        return NULL;
    }

    pthread_mutex_lock(&mut); /* lock exclusive access to variable isExecuted */
    tmp = isExecuted;
    isExecuted = tmp + 1;
    pthread_mutex_unlock(&mut); /* release the lock */

    /* these two lines are required for proper thread termination */
    serverThreads[threadArgs->threadIndex].status = THREAD_FINISHED;
    pthread_cond_signal(&threadCond);

    close(threadArgs->newsockfd); /* important to avoid memory leak */
    free(threadArgs);
    pthread_exit(&returnValue);
}

/* finds unused thread info slot; allocates more slots if necessary
   only called by main thread */
int findThreadIndex()
{
    int i, tmp;

    for (i = 0; i < noOfThreads; i++)
    {
        if (serverThreads[i].status == THREAD_AVAILABLE)
        {
            serverThreads[i].status = THREAD_IN_USE;
            return i;
        }
    }

    /* no available thread found; need to allocate more threads */
    pthread_rwlock_wrlock(&threadLock);
    serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
    noOfThreads = noOfThreads + THREADS_ALLOCATED;
    pthread_rwlock_unlock(&threadLock);
    if (serverThreads == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    /* initialise thread status */
    for (tmp = i + 1; tmp < noOfThreads; tmp++)
    {
        serverThreads[tmp].status = THREAD_AVAILABLE;
    }
    serverThreads[i].status = THREAD_IN_USE;
    return i;
}

/* waits for threads to finish and releases resources used by the thread management functions. You don't need to modify this function */
void *waitForThreads(void *args)
{
    int i, res;
    while (1)
    {
        pthread_mutex_lock(&threadEndLock);
        pthread_cond_wait(&threadCond, &threadEndLock);
        pthread_mutex_unlock(&threadEndLock);

        pthread_rwlock_rdlock(&threadLock);
        for (i = 0; i < noOfThreads; i++)
        {
            if (serverThreads[i].status == THREAD_FINISHED)
            {
                res = pthread_join(serverThreads[i].pthreadInfo, NULL);
                if (res != 0)
                {
                    fprintf(stderr, "thread joining failed, exiting\n");
                    exit(1);
                }
                serverThreads[i].status = THREAD_AVAILABLE;
            }
        }
        pthread_rwlock_unlock(&threadLock);
    }
}

int main(int argc, char *argv[])
{

    socklen_t clilen;
    int sockfd, portno;
    struct sockaddr_in6 serv_addr, cli_addr;
    int result;
    pthread_t waitInfo;
    pthread_attr_t waitAttributes;

    if (argc < 2)
    {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

    /* create socket */
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(portno);

    /* bind it */
    if (bind(sockfd, (struct sockaddr *)&serv_addr,
             sizeof(serv_addr)) < 0)
        error("ERROR on binding");

    /* ready to accept connections */
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    /* create separate thread for waiting  for other threads to finish */
    if (pthread_attr_init(&waitAttributes))
    {
        fprintf(stderr, "Creating initial thread attributes failed!\n");
        exit(1);
    }

    result = pthread_create(&waitInfo, &waitAttributes, waitForThreads, NULL);
    if (result != 0)
    {
        fprintf(stderr, "Initial Thread creation failed!\n");
        exit(1);
    }

    /* now wait in an endless loop for connections and process them */
    while (1)
    {

        struct threadArgs_t *threadArgs; /* must be allocated on the heap to prevent variable going out of scope */
        int threadIndex;

        threadArgs = malloc(sizeof(struct threadArgs_t));
        if (!threadArgs)
        {
            fprintf(stderr, "Memory allocation failed!\n");
            exit(1);
        }

        /* waiting for connections */
        threadArgs->newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (threadArgs->newsockfd < 0)
            error("ERROR on accept");

        /* create thread for processing of connection */
        threadIndex = findThreadIndex();
        threadArgs->threadIndex = threadIndex;
        if (pthread_attr_init(&(serverThreads[threadIndex].attributes)))
        {
            fprintf(stderr, "Creating thread attributes failed!\n");
            exit(1);
        }

        result = pthread_create(&(serverThreads[threadIndex].pthreadInfo), &(serverThreads[threadIndex].attributes), processRequest, (void *)threadArgs);
        if (result != 0)
        {
            fprintf(stderr, "Thread creation failed!\n");
            exit(1);
        }
    }
}
