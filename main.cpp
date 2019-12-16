#include <iostream>
#include <vector>
#include <fstream>
#include <map>
#include <sstream>
#include <unistd.h>
#include <bitset>

#define passlen_bytes 4
#define blocklen_bytes 4


struct arguments {
    bool oflag = false;
    bool pflag = false;
    bool Pflag = false;
    std::string opentext_fn = "opentext.txt";
    std::string password = "passerr";
    std::string paswwrord_fn = "password.txt";
} typedef args;

args arguments_parse(int argc, char** argv);
void argument_check(args args, std::vector<unsigned char>& opn, std::vector<unsigned char>& pass);
void print_help();
unsigned int get_filesize(std::string filename);
std::vector<unsigned char> get_content(std::string filename, int len=0);
std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass);
std::vector<std::bitset<8 * blocklen_bytes>>
add_last_block(std::vector<std::bitset<8 * blocklen_bytes>> open_blocks, std::vector<unsigned char> last_block);
std::bitset<8*blocklen_bytes> round(std::bitset<8*blocklen_bytes> X, std::bitset<8*blocklen_bytes> k);

int main(int argc, char** argv) {
    args arguments = arguments_parse(argc, argv);

    std::vector<unsigned char> opentext;
    std::vector<unsigned char> closetext;
    std::vector<unsigned char> password;

    argument_check(arguments, opentext, password);
    encrypt_text(opentext, password);

    return 0;
}


//bitset устанавливает в обратном порядке, то есть bitset[0] -- младший бит.
std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass) {
    std::vector<std::bitset<8*blocklen_bytes>> open_blocks = std::vector<std::bitset<8*blocklen_bytes>>();
    int full_blocks = (open.size()-open.size()%blocklen_bytes)/blocklen_bytes;
    for (int i = 0; i<full_blocks; i++) {
        int ptr = i*blocklen_bytes;
        std::bitset<8> test(open[ptr]);
        unsigned long long block = ((open[ptr+3]<<24) + (open[ptr+2]<<16) + (open[ptr+1] << 8) + open[ptr+0]); //вот тут используется то, что длина блока равна 4. Хорошо бы сделать универсально.
        open_blocks.push_back(std::bitset<8*blocklen_bytes>(block));
    }
    open_blocks = add_last_block(open_blocks, std::vector<unsigned char>(open.begin() + full_blocks*blocklen_bytes, open.end()));

    std::bitset<8*blocklen_bytes> oddK((pass[3]<<24)+pass[2]<<16)+(pass[1]<<8)+(pass[0]);
    ()




    std::vector<unsigned char> toRet(0);
    return toRet;


//    return std::vector<unsigned char>(std::string("a").begin(), std::string("a").end());
}

std::bitset<8*blocklen_bytes> round(std::bitset<8*blocklen_bytes> X, std::bitset<8*blocklen_bytes> k) {

}

std::vector<std::bitset<8 * blocklen_bytes>>
add_last_block(std::vector<std::bitset<8 * blocklen_bytes>> open_blocks, std::vector<unsigned char> last_block) {
    unsigned long long last_block_size = last_block.size();

    std::vector<unsigned char> full_block(blocklen_bytes);
    for (int i = 0; i<blocklen_bytes; i++) {
        if (i < last_block_size) {
            full_block[i] = last_block[i];
        }
        else {
            break;
        }
    }
    std::vector<std::bitset<8*blocklen_bytes>> result = open_blocks;
    result.push_back(std::bitset<8*blocklen_bytes>((full_block[3]<<24) + (full_block[2]<<16) + (full_block[1]<<8)+full_block[0]));
    result.push_back(std::bitset<8*blocklen_bytes>(last_block_size));
    return result;
}

void argument_check(args args, std::vector<unsigned char>& opn, std::vector<unsigned char>& pass) {
    if (args.oflag) {
        opn = get_content(args.opentext_fn);
    }
    if (args.pflag) {
        if (args.password == "lenerror") {
            std::cerr << "Len of pass. Should be "<< passlen_bytes <<" bytes long";
            exit(1);
        }
        pass = std::vector<unsigned char>(args.password.begin(), args.password.end());
    }
    if (args.Pflag) {
        pass = get_content(args.paswwrord_fn, passlen_bytes);
        if (pass.size() < passlen_bytes) {
            std::cerr << "Password should be "<<passlen_bytes <<" bytes long" << std::endl;
            exit(1);
        }
    }

}

unsigned int get_filesize(std::string filename){
    unsigned int filesize;
    std::ifstream file(filename, std::ifstream::ate | std::ifstream::binary);
    if (!file.is_open()){
        std::cerr << "Can not open file " << filename << std::endl;
        exit(1);
    }
    file.unsetf(std::ios::skipws); //not cut whitespaces
    filesize = file.tellg();
    file.close();
    return filesize;
}

std::vector<unsigned char> get_content(std::string filename, int len){
    std::vector<unsigned char> product;
    unsigned int filesize = get_filesize(filename);
    if (filesize == 0) {
        return product;
    }
    std::ifstream file(filename, std::ifstream::binary);
    file.unsetf(std::ios::skipws); //not cut whitespaces
    product.resize(filesize);

    /**
     * Read whole file.
     */
    file.read((char*) &product[0], len ? len : filesize);
    file.close();
    return product;
}

args arguments_parse(int argc, char** argv) {
    args args;
    int c;
    while ((c = getopt(argc, argv, ":ho::p:P::")) != -1) {
        switch(c) {
            case 'h':{
                print_help();
                exit(0);
            }
            case 'o': {
                if (args.oflag) {
                    std::cerr << "Only one file by run" << std::endl;
                    exit(1);
                }
                args.oflag = true;
                args.opentext_fn = optarg ? optarg : "opentext.txt";
                break;
            }
            case 'p': {
                if (args.pflag) {
                    std::cerr << "Only one password by run";
                    exit(1);
                }
                args.pflag = true;
                if (strlen(optarg) == 4) {
                    args.password = optarg;
                } else {
                    args.password = "lenerror";
                }
                break;
            }
            case 'P': {
                if (args.Pflag) {
                    std::cerr << "Only one password by run";
                    exit(1);
                }
                args.Pflag = true;
                args.paswwrord_fn = optarg ? optarg : "password.txt";
                break;
            }
            case '?': {
                if (isprint(optopt)) {
                    std::cerr << "Unknown option -" << static_cast<char>(optopt) << "." << std::endl;
                    exit(1);
                }
                else {
                    std::cerr << "Unknown option" << std::endl;
                }
                break;
            }
            case ':': {
                std::cerr << "Option -" << static_cast<char>(optopt) << " requires an argument." << std::endl;
                exit(1);
            }
            default:
                exit(1);
        }
    }
    if (optind != argc) {
        std::cerr << "problem with some arguments." << std::endl;
        print_help();
        exit(1);
    }
    if (!args.pflag && !args.Pflag) {
        args.Pflag = true;
        args.paswwrord_fn = "password.txt";
    }
    if (!args.oflag) {
        args.oflag = true;
        args.opentext_fn = "opentext.txt";
    }
    return args;
}

void print_help() {
    std::cout << "===========" << std::endl;
    std::cout << "HELP" << std::endl;
    std::cout << "===========" << std::endl;
    std::cout << "-h\n"
                 "\t Prints this help" << std::endl;
    std::cout <<
                "-o OPENTEXT filename\n" <<
                "-p PASSWORD\n" <<
                "-P PASSWORD filename\n"
    << std::endl;
}