/**
 * @file myfw.cpp
 * @author Frog2022 (zhehao4423@gmail.com)
 * @brief process user input
 * @date 2024/07
 */
#include <iostream>
#include <string.h>
#include <cstring>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

// include c header files and have access to c source files.
// This is used to avoid error "undefined reference to xxx" in the linking process.
extern "C" {
#include "api.h"
#include "call.h"
#include "share.h"
#include "comm_protocol.h"
}

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

static Name table_name = "", chain_name = "", rule_name = "";

unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;
char rule_name[MAX_NAME_LENGTH+1];
char front_name[MAX_NAME_LENGTH+1];
char replace_name[MAX_NAME_LENGTH+1];
char log_rule_name[MAX_NAME_LENGTH+1];
unsigned int rule_action = 0;

// unsigned int chain_priority = 0;
// unsigned int chain_type = 0;
// unsigned int chain_hook = 0;
// unsigned int chain_action = 0;
static ChainT chain;
static struct FilterRule_Chain ftchain;
static Name chain_rename_name = "";

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
                << programName << " add rule <table> <chain> -r <rule name> -p <protocol> -x <saddr> -y <daddr> -m <srcport> -n <dstport> -a <action, deny or accept>" << std::endl
                << "  insert rule   Insert a rule at a specific position in the chain" << std::endl
                << programName << " insert rule <table> <chain> -f <front rule name> -r <rule name> -p <protocol> -x <saddr> -y <daddr> -m <srcport> -n <dstport> -a <action, deny or accept>" << std::endl
                << "  replace rule  Replace an existing rule in the chain" << std::endl
                << programName << " replace rule <table> <chain> -f <front rule name> -r <rule name> -p <protocol> -x <saddr> -y <daddr> -m <srcport> -n <dstport> -a <action, <action, deny or accept>" << std::endl
                << "  delete rule   Delete a rule from the chain" << std::endl
                << programName << " delete rule <table> <chain> -r <rule name>" << std::endl
                << "  add chain     Add a chain to the specified table" << std::endl
                << programName << " add chain <table> <chain name> -t <type, filter or nat> -h <hook, input or output> -p <priority, an unsigned int> -a <action, deny or accept>" << std::endl
                << "  delete rule   Delete a chain from the table" << std::endl
                << programName << " delete chain <table> <chain name>" << std::endl
                << "  list chain    List all rules in a specific chain" << std::endl
                << programName << " insert chain <table> <chain name>" << std::endl
                << "  flush chain   Flush all rules in a specific chain" << std::endl
                << programName << " flush chain <table> <chain name>" << std::endl
                << "  rename chain  Replace an existing chain in the table" << std::endl
                << programName << " replace chain <table> <chain> -n <new chain name>" << std::endl
                << "  view log      view logs of the rule by name" << std::endl
                << programName << " view log <table> <chain> -r <rule_name_1> -r <rule_name_2> ... -r <rule_name_n>" << std::endl
                << "Options:" << std::endl
                << "  -h             Print this help message" << std::endl;
    // TODO: Add descriptions for other options if needed
}

void viewLogs(int argc, char *argv[]){
    int optret;
    optret = getopt(argc,argv,"r");
    while( optret != -1 ) {
        // printf(" first in getpara: %s\n",argv[optind]);
        switch( optret ) {
            case 'r': // rule name
                std::strncpy(log_rule_name, argv[optind], MAX_NAME_LENGTH);
                log_rule_name[MAX_NAME_LENGTH+1] = '\0';

                struct KernelResp rsp = getLogs(log_rule_name, table_name, chain_name);
                ProcKernelResp(rsp);
                break;
            
            default:
            printf("Invalid parameters! \n ");
                printHelp(argv[0]);
                exit(1);;
        }
        optret = getopt(argc,argv,"r");
    }
}

void getRulePara(Command cmd, int argc, char *argv[]){
	int optret;

	unsigned int tmpport;
    unsigned int isLog;
    struct KernelResp rsp;

    switch (cmd)
    {
        case Command::Add:
            optret = getopt(argc,argv,"rpxymnal");
            while( optret != -1 ) {
                // printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'r': // rule name
                        std::strncpy(u_ftRule.name, argv[optind], MAX_NAME_LENGTH);
                        u_ftRule.name[MAX_NAME_LENGTH+1] = '\0';
                        break;
                    case 'p':
                        std::strncpy(u_ftRule.protocol, argv[optind], 5);
                        u_ftRule.protocol[6] = '\0';
                        break;
                    case 'x':   //get source ipaddr 
                        std::strncpy(u_ftRule.sip, argv[optind], sizeof(u_ftRule.sip) - 1);
                        u_ftRule.sip[sizeof(u_ftRule.sip) - 1] = '\0';
                        break;
                    case 'y':   //get destination ipaddr
                        std::strncpy(u_ftRule.tip, argv[optind], sizeof(u_ftRule.tip) - 1);
                        u_ftRule.tip[sizeof(u_ftRule.tip) - 1] = '\0';
                        break;
                    case 'm':   //get source port
                    std::strncpy(u_ftRule.sport, argv[optind], sizeof(u_ftRule.sport) - 1);
                    u_ftRule.sport[sizeof(u_ftRule.sport) - 1] = '\0';
                        break;
                    case 'n':   //get destination port
                    std::strncpy(u_ftRule.tport, argv[optind], sizeof(u_ftRule.tport) - 1);
                    u_ftRule.tport[sizeof(u_ftRule.tport) - 1] = '\0';
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
                    u_ftRule.act = rule_action;
                        break;
                    case 'l': // is log or not
                        isLog = atoi(argv[optind]);
                        if(isLog == 0 || isLog == 1){
                            u_ftRule.islog = isLog;
                        }
                        else{
                            printf("Unkonwn isLog para! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"rpxymnal");
            }

            std::strncpy(u_ftRule.name, rule_name, MAX_NAME_LENGTH);
            std::strncpy(k_ftRule.name, rule_name, MAX_NAME_LENGTH);

            rsp = addFtRule(&u_ftRule, table_name, chain_name);
            ProcKernelResp(rsp);
            break;
        
        case Command::Insert:
            optret = getopt(argc,argv,"frpxymnal");
            while( optret != -1 ) {
                //printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'f':
                        std::strncpy(front_name, argv[optind], MAX_NAME_LENGTH);
                        front_name[MAX_NAME_LENGTH+1] = '\0';
                        break;
                    case 'r': // rule name
                        std::strncpy(u_ftRule.name, argv[optind], MAX_NAME_LENGTH);
                        u_ftRule.name[MAX_NAME_LENGTH+1] = '\0';
                        break;
                    case 'p':
                        std::strncpy(u_ftRule.protocol, argv[optind], 5);
                        u_ftRule.protocol = '\0';
                        break;
                    case 'x':   //get source ipaddr 
                        std::strncpy(u_ftRule.sip, argv[optind], sizeof(u_ftRule.sip) - 1);
                        u_ftRule.sip[sizeof(u_ftRule.sip) - 1] = '\0';
                        break;
                    case 'y':   //get destination ipaddr
                        std::strncpy(u_ftRule.tip, argv[optind], sizeof(u_ftRule.tip) - 1);
                        u_ftRule.tip[sizeof(u_ftRule.tip) - 1] = '\0';
                        break;
                    case 'm':   //get source port
                    std::strncpy(u_ftRule.sport, argv[optind], sizeof(u_ftRule.sport) - 1);
                    u_ftRule.sport[sizeof(u_ftRule.sport) - 1] = '\0';
                        break;
                    case 'n':   //get destination port
                    std::strncpy(u_ftRule.tport, argv[optind], sizeof(u_ftRule.tport) - 1);
                    u_ftRule.tport[sizeof(u_ftRule.tport) - 1] = '\0';
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
                    u_ftRule.act = rule_action;
                        break;
                    case 'l': // is log or not
                        isLog = atoi(argv[optind]);
                        if(isLog == 0 || isLog == 1){
                            u_ftRule.islog = isLog;
                        }
                        else{
                            printf("Unkonwn isLog para! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"frpxymnal");
            }

            // TODO: deal with insert rule i
            struct KernelResp rsp = insertFtRule(&u_ftRule, front_name, table_name, chain_name);
            ProcKernelResp(rsp);
            break;

        case Command::Delete:   // TODO: change delete to by name, not by index
            optret = getopt(argc,argv,"r");
            while( optret != -1 ) {
                //printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'r':
                        std::strcpy(rule_name, argv[optind], MAX_NAME_LENGTH);
                        rule_name[MAX_NAME_LENGTH+1] = '\0';
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"r");
            }


            rsp = delFTRule(rule_name, table_name, chain_name);
            ProcKernelResp(rsp);
            break;

        case Command::Replace:
            optret = getopt(argc,argv,"frpxymnal");
            while( optret != -1 ) {
                //printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'f':
                        std::strncpy(replace_name, argv[optind], MAX_NAME_LENGTH);
                        replace_name[MAX_NAME_LENGTH+1] = '\0';
                        break;
                    case 'r':
                        std::strcpy(rule_name, argv[optind], MAX_NAME_LENGTH);
                        rule_name[MAX_NAME_LENGTH+1] = '\0';
                        break;
                    case 'p':
                        std::strncpy(u_ftRule.protocol, argv[optind], 5);
                        u_ftRule.protocol = '\0';
                    case 'x':   //get source ipaddr 
                        std::strncpy(u_ftRule.sip, argv[optind], sizeof(u_ftRule.sip) - 1);
                        u_ftRule.sip[sizeof(u_ftRule.sip) - 1] = '\0';
                        break;
                    case 'y':   //get destination ipaddr
                        std::strncpy(u_ftRule.tip, argv[optind], sizeof(u_ftRule.tip) - 1);
                        u_ftRule.tip[sizeof(u_ftRule.tip) - 1] = '\0';
                        break;
                    case 'm':   //get source port
                    std::strncpy(u_ftRule.sport, argv[optind], sizeof(u_ftRule.sport) - 1);
                    u_ftRule.sport[sizeof(u_ftRule.sport) - 1] = '\0';
                        break;
                    case 'n':   //get destination port
                    std::strncpy(u_ftRule.tport, argv[optind], sizeof(u_ftRule.tport) - 1);
                    u_ftRule.tport[sizeof(u_ftRule.tport) - 1] = '\0';
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
                    u_ftRule.act = rule_action;
                        break;
                    case 'l': // is log or not
                        isLog = atoi(argv[optind]);
                        if(isLog == 0 || isLog == 1){
                            u_ftRule.islog = isLog;
                        }
                        else{
                            printf("Unkonwn isLog para! please check and try again! \n");
                            exit(1);
                        }
                        break;
                    default:
                    printf("Invalid parameters! \n ");
                        printHelp(argv[0]);
                        exit(1);;
                }
                optret = getopt(argc,argv,"frpxymnal");
            }

            // TODO: deal with delete rule and insert rule
            struct KernelResp rsp = insertFtRule(&u_ftRule, replace_name, table_name, chain_name);
            ProcKernelResp(rsp);
            rsp = delFTRule(replace_name, table_name, chain_name);
            ProcKernelResp(rsp);
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
    struct KernelResp rsp;
    switch (cmd)
    {
        case Command::Add:
            optret = getopt(argc,argv,"thpa");
            while( optret != -1 ) {
                // printf(" first in getpara: %s\n",argv[optind]);
                switch( optret ) {
                    case 'p': // get chain priority
                    try {
                        chain.priority = (ChainPriority)std::stoi(argv[optind]);
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Invalid argument: " << e.what() << std::endl;
                    } catch (const std::out_of_range& e) {
                        std::cerr << "Out of range: " << e.what() << std::endl;
                    }
                        break;
                    case 't':   // get chain type
                    if (strncmp(argv[optind], "filter",5) == 0 )
                        chain.type = CHAIN_FILTER;
                    else if (strncmp(argv[optind], "nat",3) == 0  )
                        chain.type = CHAIN_NAT;
                    else {
                        printf("Unkonwn chain type! please check and try again! \n");
                        exit(1);
                    }
                        break;
                    case 'h':   // get the hook to load on
                    if (strncmp(argv[optind], "input",5) == 0 ) {
                        chain.hook = NF_INET_LOCAL_IN;
                        ftchain.applyloc = LOCALIN;
                    } else if (strncmp(argv[optind], "output",3) == 0  ) {
                        chain.hook = NF_INET_LOCAL_OUT;
                        ftchain.applyloc = LOCALOUT;
                    } else {
                        printf("Unkonwn chain type! please check and try again! \n");
                        exit(1);
                    }
                        break;
                    case 'a':   // get chain policy when it's a filter chain
                    if (strncmp(argv[optind], "accept",5) == 0 )
                            chain.chain.filter.policy = CHAIN_ACCEPT;
                        else if ( strncmp(argv[optind], "deny",4) == 0  )
                            chain.chain.filter.policy = CHAIN_DROP;
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

            // get chain name
            std::strncpy(chain.name, chain_name, MAX_NAME_LENGTH);
            std::strncpy(ftchain.name, chain_name, MAX_NAME_LENGTH);


            // deal with add chain
            // rsp = addChain(&chain, table_name);
            rsp = addFTChain(&ftchain, table_name);
            ProcKernelResp(rsp);
            break;
        
        case Command::List:
            
            // deal with list chain by name
            struct KernelResp rsp = listChain(chain_name, table_name);
            ProcKernelResp(rsp);
            break;

        case Command::Flush:
            
            // deal with flush chain by name
            struct KernelResp rsp = flushChain(chain_name, table_name);
            ProcKernelResp(rsp);
            break;

        case Command::Delete:
        
            // deal with delete chain by name    
            // rsp = delChain(chain_name, table_name);
            rsp = delFTChain(chain_name, table_name);
            ProcKernelResp(rsp);
            break;

        case Command::Rename:
            optret = getopt(argc,argv,"n");
            if( optret != -1 ) {
                std::strncpy(chain_rename_name, argv[optind], MAX_NAME_LENGTH);
            }
            else{
                printf("Invalid parameters! \n ");
                printHelp(argv[0]);
                exit(1);;
            }
            

            // TODO: deal with rename chain by name
            struct KernelResp rsp = renameChain(chain_name, chain_rename_name, table_name);
            ProcKernelResp(rsp);
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
    std::string object;
    
    int optionsStartIndex = 1; // Start with the command itself

    // First argument is the command, so start checking from the second argument
    for (int i = 2; i < argc; ++i) {
        if (i < argc && argv[i][0] != '-') {
            if (object.empty()) {
                object = argv[i];
            }
            else if (table_name[0] == '\0') {
                std::strncpy(table_name, argv[i], MAX_NAME_LENGTH);
            } else if (chain_name[0] == '\0') {
                std::strncpy(chain_name, argv[i], MAX_NAME_LENGTH);
            } else if (rule_name[0] == '\0') {
                std::strncpy(rule_name, argv[i], MAX_NAME_LENGTH);
                optionsStartIndex = i + 1; // Set the index to start collecting options
                break; 
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
        std::cout << "Table: " << table_name << std::endl;
        std::cout << "Chain: " << chain_name << std::endl;
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
        std::cout << "Table: " << table_name << std::endl;
        std::cout << "Chain: " << chain_name << std::endl;
        std::cout << "Options:";
        std::cout <<  chain.type << " " << chain.hook << " " << 
                chain.priority << " " << chain.chain.filter.policy << " " << 
                chain_rename_name << std::endl;
    }
    else if(cmd == Command::View && (object == "log" || object == "logs")){
        viewLogs(newArgc, newArgv);
    }

    return 0;
}