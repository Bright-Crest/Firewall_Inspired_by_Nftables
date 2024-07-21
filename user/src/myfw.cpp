// TODO: print the rules or chains
// TODO: print the log
// TODO: add rule name
// TODO: add rule islog

#include <iostream>
#include <string.h>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "user_comm.h"
#include "api.h"



enum class Command {
    Add,
    Insert,
    Replace,
    Delete,
    List,
    Flush,
    Rename,
    View,
    Unknown
};

ftrule u_ftRule;
FTRule k_ftRule;

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;
unsigned int insert_index = 0; 
unsigned int delete_index = 0; 
unsigned int replace_index = 0; 
unsigned int rule_action = 0;

unsigned int chain_priority = 0;
unsigned int chain_type = 0;
unsigned int chain_hook = 0;
unsigned int chain_action = 0;
std::string chain_rename_name = "";

std::string commandToString(Command cmd) {
    switch(cmd) {
        case Command::Add: return "add";
        case Command::Insert: return "insert";
        case Command::Replace: return "replace";
        case Command::Delete: return "delete";
        case Command::List: return "list";
        case Command::Flush: return "flush";
        case Command::Rename: return "rename";
        case Command::View: return "view";
        default: return "unknown";
    }
}

Command parseCommand(const std::string& command) {
    if (command == "add") return Command::Add;
    if (command == "insert") return Command::Insert;
    if (command == "replace") return Command::Replace;
    if (command == "delete") return Command::Delete;
    if (command == "list") return Command::List;
    if (command == "flush") return Command::Flush;
    if (command == "rename") return Command::Rename;
    if (command == "View") return Command::View;
    return Command::Unknown; // Default to 'Unknown' if not recognized
}

void printHelp(const char* programName) {
    std::cout << "Usage: " << programName << " <command> <object> <table> <chain> [options...]" << std::endl
                << "Commands:" << std::endl
                << "  add rule      Add a rule to the specified chain" << std::endl
                << programName << " add rule <table> <chain> -p <protocol> -x <saddr> -y <daddr> -m <srcport> -n <dstport> -a <action, deny or accept>" << std::endl
                << "  insert rule   Insert a rule at a specific position in the chain" << std::endl
                << programName << " insert rule <table> <chain> -i <index> -p <protocol> -x <saddr> -y <daddr> -m <srcport> -n <dstport> -a <action, deny or accept>" << std::endl
                << "  replace rule  Replace an existing rule in the chain" << std::endl
                << programName << " replace rule <table> <chain> -i <index> -p <protocol> -x <saddr> -y <daddr> -m <srcport> -n <dstport> -a <action, <action, deny or accept>" << std::endl
                << "  delete rule   Delete a rule from the chain" << std::endl
                << programName << " delete rule <table> <chain> -i <index>" << std::endl
                << "  add chain     Add a chain to the specified table" << std::endl
                << programName << " add chain <table> <chain name> -t <type, filter or nat> -h <hook, input or output> -p <priority, an unsigned int> -a <action, deny or accept>" << std::endl
                << "  delete rule   Delete a chain from the table" << std::endl
                << programName << " delete chain <table> <chain name>" << std::endl
                << "  list chain    List all rules in a specific chain" << std::endl
                << programName << " insert chain <table> <chain name>" << std::endl
                << "  flush chain   flush all rules in a specific chain" << std::endl
                << programName << " flush chain <table> <chain name>" << std::endl
                << "  rename chain  Replace an existing chain in the table" << std::endl
                << programName << " replace chain <table> <chain> -n <new chain name>" << std::endl
                << "Options:" << std::endl
                << "  -h             Print this help message" << std::endl;
    // TODO: Add descriptions for other options if needed
}

void viewLogs(int argc, char *argv[]){
    // TODO: viewLogs
}

void getRulePara(Command cmd, int argc, char *argv[]){
	int optret;
	unsigned short tmpport;
    switch (cmd)
    {
        case Command::Add:
            optret = getopt(argc,argv,"pxymna");
            while( optret != -1 ) {
                // printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'p':
                        if (strncmp(argv[optind], "ping",4) == 0 ){
                            u_ftRule.protocol = "ping";
                            k_ftRule.protocol = PROTOCOL_PING;
                        }
                        else if ( strncmp(argv[optind], "tcp",3) == 0  ){
                            u_ftRule.protocol = "tcp";
                            k_ftRule.protocol = PROTOCOL_TCP;
                        }
                        else if ( strncmp(argv[optind], "udp",3) == 0 ){
                            u_ftRule.protocol = "udp";
                            k_ftRule.protocol = PROTOCOL_UDP;
                        }
                        else if ( strncmp(argv[optind], "any",3) == 0 ){
                            u_ftRule.protocol = "any";
                            k_ftRule.protocol = PROTOCOL_ANY;
                        }
                        else {
                            printf("Unkonwn protocol! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    case 'x':   //get source ipaddr 
                    if ( inet_aton(argv[optind], (struct in_addr* )&controlled_saddr) == 0){
                        printf("Invalid source ip address! please check and try again! \n ");
                        exit(1);
                    }
                    else{
                        std::strncpy(u_ftRule.sip, argv[optind], sizeof(u_ftRule.sip) - 1);
                        u_ftRule.sip[sizeof(u_ftRule.sip) - 1] = '\0';
                        k_ftRule.saddr = controlled_saddr;
                        k_ftRule.smask = 0;
                    }
                        break;
                    case 'y':   //get destination ipaddr
                    if ( inet_aton(argv[optind], (struct in_addr* )&controlled_daddr) == 0){
                        printf("Invalid destination ip address! please check and try again! \n ");
                        exit(1);
                    }
                    else{
                        std::strncpy(u_ftRule.tip, argv[optind], sizeof(u_ftRule.tip) - 1);
                        u_ftRule.tip[sizeof(u_ftRule.tip) - 1] = '\0';
                        k_ftRule.taddr = controlled_daddr;
                        k_ftRule.tmask = 0;
                    }
                        break;
                    case 'm':   //get source port
                    std::strncpy(u_ftRule.sport, argv[optind], sizeof(u_ftRule.sport) - 1);
                    u_ftRule.sport[sizeof(u_ftRule.sport) - 1] = '\0';
                    tmpport = atoi(argv[optind]);
                    if (tmpport == 0){
                        printf("Invalid source port! please check and try again! \n ");
                        exit(1);
                    }
                    k_ftRule.sport = htons(tmpport);
                        break;
                    case 'n':   //get destination port
                    std::strncpy(u_ftRule.tport, argv[optind], sizeof(u_ftRule.tport) - 1);
                    u_ftRule.tport[sizeof(u_ftRule.tport) - 1] = '\0';
                    tmpport = atoi(argv[optind]);
                    if (tmpport == 0){
                        printf("Invalid destination port! please check and try again! \n ");
                        exit(1);
                    }
                    k_ftRule.tport = htons(tmpport);
                        break;

                    case 'a':   //get destination port
                    if (strncmp(argv[optind], "accept",5) == 0 )
                        rule_action = ACTION_ACCEPT;
                    else if ( strncmp(argv[optind], "deny",4) == 0  )
                        rule_action = ACTION_DENY;
                    else {
                        printf("Unkonwn action! please check and try again! \n");
                        exit(1);
                    }
                    u_ftRule.act = k_ftRule.act = rule_action;
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"pxymna");
            }

            // TODO: deal with add rule
            break;
        
        case Command::Insert:
            optret = getopt(argc,argv,"ipxymna");
            while( optret != -1 ) {
                //printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'i':
                        insert_index = atoi(argv[optind]);
                        break;
                    case 'p':
                        if (strncmp(argv[optind], "ping",4) == 0 )
                            controlled_protocol = 1;
                        else if ( strncmp(argv[optind], "tcp",3) == 0  )
                            controlled_protocol = 6;
                        else if ( strncmp(argv[optind], "udp",3) == 0 )
                            controlled_protocol = 17;
                        else {
                            printf("Unkonwn protocol! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    case 'x':   //get source ipaddr 
                    if ( inet_aton(argv[optind], (struct in_addr* )&controlled_saddr) == 0){
                        printf("Invalid source ip address! please check and try again! \n ");
                        exit(1);
                    }
                        break;
                    case 'y':   //get destination ipaddr
                    if ( inet_aton(argv[optind], (struct in_addr* )&controlled_daddr) == 0){
                        printf("Invalid destination ip address! please check and try again! \n ");
                        exit(1);
                    }
                        break;
                    case 'm':   //get source port
                    tmpport = atoi(argv[optind]);
                    if (tmpport == 0){
                        printf("Invalid source port! please check and try again! \n ");
                        exit(1);
                    }
                    controlled_srcport = htons(tmpport);
                        break;
                    case 'n':   //get destination port
                    tmpport = atoi(argv[optind]);
                    if (tmpport == 0){
                        printf("Invalid destination port! please check and try again! \n ");
                        exit(1);
                    }
                    controlled_dstport = htons(tmpport);
                        break;

                    case 'a':   //get destination port
                    if (strncmp(argv[optind], "accept",5) == 0 )
                            rule_action = ACTION_ACCEPT;
                        else if ( strncmp(argv[optind], "deny",4) == 0  )
                            rule_action = ACTION_DENY;
                        else {
                            printf("Unkonwn action! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"ipxymna");
            }

            // TODO: deal with insert rule i
            break;

        case Command::Delete:   // TODO: change delete to by name, not by index
            optret = getopt(argc,argv,"i");
            while( optret != -1 ) {
                //printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'i':
                        delete_index = atoi(argv[optind]);
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"i");
            }

            // TODO: deal with delete rule i
            break;

        case Command::Replace:
            optret = getopt(argc,argv,"ipxymna");
            while( optret != -1 ) {
                //printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'i':
                        replace_index = atoi(argv[optind]);
                        break;
                    case 'p':
                        if (strncmp(argv[optind], "ping",4) == 0 )
                            controlled_protocol = PROTOCOL_PING;
                        else if ( strncmp(argv[optind], "tcp",3) == 0  )
                            controlled_protocol = PROTOCOL_TCP;
                        else if ( strncmp(argv[optind], "udp",3) == 0 )
                            controlled_protocol = PROTOCOL_UDP;
                        else if ( strncmp(argv[optind], "any",3) == 0 )
                            controlled_protocol = PROTOCOL_ANY;
                        else {
                            printf("Unkonwn protocol! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    case 'x':   //get source ipaddr 
                    if ( inet_aton(argv[optind], (struct in_addr* )&controlled_saddr) == 0){
                        printf("Invalid source ip address! please check and try again! \n ");
                        exit(1);
                    }
                        break;
                    case 'y':   //get destination ipaddr
                    if ( inet_aton(argv[optind], (struct in_addr* )&controlled_daddr) == 0){
                        printf("Invalid destination ip address! please check and try again! \n ");
                        exit(1);
                    }
                        break;
                    case 'm':   //get source port
                    tmpport = atoi(argv[optind]);
                    if (tmpport == 0){
                        printf("Invalid source port! please check and try again! \n ");
                        exit(1);
                    }
                    controlled_srcport = htons(tmpport);
                        break;
                    case 'n':   //get destination port
                    tmpport = atoi(argv[optind]);
                    if (tmpport == 0){
                        printf("Invalid destination port! please check and try again! \n ");
                        exit(1);
                    }
                    controlled_dstport = htons(tmpport);
                        break;

                    case 'a':   //get destination port
                    if (strncmp(argv[optind], "accept",5) == 0 )
                            rule_action = ACTION_ACCEPT;
                        else if ( strncmp(argv[optind], "deny",4) == 0  )
                            rule_action = ACTION_DENY;
                        else {
                            printf("Unkonwn action! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"ipxymna");
            }

            // TODO: deal with delete rule i and insert rule i
            break;

        default:
            printf("Invalid parameters! \n ");
            printHelp(argv[0]);
            exit(1);;
            break;
        }
	
}


void getChainPara(Command cmd, int argc, char *argv[]){
	int optret;
    switch (cmd)
    {
        case Command::Add:
            optret = getopt(argc,argv,"thpa");
            while( optret != -1 ) {
                // printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'p':
                    try {
                        chain_priority = std::stoi(argv[optind]);
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Invalid argument: " << e.what() << std::endl;
                    } catch (const std::out_of_range& e) {
                        std::cerr << "Out of range: " << e.what() << std::endl;
                    }
                        break;
                    case 't':   //get source ipaddr 
                    if (strncmp(argv[optind], "filter",5) == 0 )
                        chain_type = CHAIN_TYPE_FILTER;
                    else if (strncmp(argv[optind], "nat",3) == 0  )
                        chain_type = CHAIN_TYPE_NAT;
                    else {
                        printf("Unkonwn chain type! please check and try again! \n");
                        exit(1);
                    }
                        break;
                    case 'h':   //get destination ipaddr
                    if (strncmp(argv[optind], "input",5) == 0 )
                        chain_hook = CHAIN_HOOK_INPUT;
                    else if (strncmp(argv[optind], "output",3) == 0  )
                        chain_hook = CHAIN_HOOK_OUTPUT;
                    else {
                        printf("Unkonwn chain type! please check and try again! \n");
                        exit(1);
                    }
                        break;
                    case 'a':   //get destination port
                    if (strncmp(argv[optind], "accept",5) == 0 )
                            chain_action = ACTION_ACCEPT;
                        else if ( strncmp(argv[optind], "deny",4) == 0  )
                            chain_action = ACTION_DENY;
                        else {
                            printf("Unkonwn action! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"thpa");
            }

            // TODO: deal with add rule
            break;
        
        case Command::List:
            
            // TODO: deal with list chain by name
            break;

        case Command::Flush:
            
            // TODO: deal with Flush chain by name
            break;

        case Command::Delete:

            // TODO: deal with delete chain by name
            break;

        case Command::Rename:
            optret = getopt(argc,argv,"n");
            if( optret != -1 ) {
                chain_rename_name = std::string(argv[optind]);
            }
            else{
                printf("Invalid parameters! \n ");
                printHelp(argv[0]);
                exit(1);;
            }
            

            // TODO: deal with rename chain by name
            break;

        default:
            printf("Invalid parameters! \n ");
            printHelp(argv[0]);
            exit(1);;
            break;
        }
	
}



int main(int argc, char* argv[]) {
    if (argc < 2 || std::string(argv[1]) == "-h") { // At least command, table, and chain are required
        printHelp(argv[0]);
        return 1;
    }

    Command cmd = parseCommand(argv[1]);
    std::string object, table, chain;
    
    int optionsStartIndex = 1; // Start with the command itself

    // First argument is the command, so start checking from the second argument
    for (int i = 2; i < argc; ++i) {
        if (i < argc && argv[i][0] != '-') {
            if (object.empty()) {
                object = argv[i];
            }
            else if (table.empty()) {
                table = argv[i];
            } else {
                chain = argv[i];
                optionsStartIndex = i + 1; // Set the index to start collecting options
                break; // We've found the chain, no need to continue
            }
        } else if (std::string(argv[i]) == "-h") {
            printHelp(argv[0]);
            return 0;
        }
    }

    int newArgc= argc - optionsStartIndex + 1;
    char* newArgv[newArgc];
    if(optionsStartIndex < argc){
        for (int i = 0; i < newArgc; ++i) {
            newArgv[i] = argv[i + optionsStartIndex-1];
            // std::cout << newArgv[i] << std::endl;
        }
    }
    
    if(object == "rule"){
        if(cmd != Command::Add && cmd != Command::Insert && cmd != Command::Replace &&cmd != Command::Delete){
            std::cout << "Wrong input format!" << std::endl;
            printHelp(argv[0]);
            return 1;
        }
        getRulePara(cmd, newArgc, newArgv);
        


        // This is a test: Output the parsed command and its components
        std::cout << "Command: " << commandToString(cmd) << std::endl;
        std::cout << "Table: " << table << std::endl;
        std::cout << "Chain: " << chain << std::endl;
        std::cout << "Options:";
        std::cout << insert_index << " " << replace_index << " " << delete_index << " "
                << controlled_protocol << " " << controlled_srcport << " " <<
                controlled_dstport << " " << controlled_saddr << " " << 
                controlled_daddr << " " << insert_index << " " << 
                delete_index << " " << replace_index << std::endl;
    }
    else if(object == "chain"){
        if(cmd != Command::Add && cmd != Command::List && cmd != Command::Flush && cmd != Command::Delete && cmd != Command::Rename){
            std::cout << "Wrong input format!" << std::endl;
            printHelp(argv[0]);
            return 1;
        }
        getChainPara(cmd, newArgc, newArgv);
        


        // This is a test: Output the parsed command and its components
        std::cout << "Command: " << commandToString(cmd) << std::endl;
        std::cout << "Table: " << table << std::endl;
        std::cout << "Chain: " << chain << std::endl;
        std::cout << "Options:";
        std::cout <<  chain_type << " " << chain_hook << " " << 
                chain_priority << " " << chain_action << " " << 
                chain_rename_name << std::endl;
    }
    else if(cmd == Command::View && (object == "log" || object == "logs")){
        viewLogs(newArgc, newArgv);
    }

    return 0;
}