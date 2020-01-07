#include <iostream>
#include <vector>
#include <fstream>
#include <map>
#include <sstream>
#include <unistd.h>
#include <bitset>

#define passlen_bytes 4
#define blocklen_bytes 4
#define N (8*blocklen_bytes)
#define M 4
#define D 4


struct arguments {
    bool fflag = false;
    bool pflag = false;
    bool Pflag = false;
    bool eflag = false;
    bool dflag = false;
    std::string opentext_fn = "opentext.txt";
    std::string encryoted_fn = "encrypted.txt";
    std::string password = "passerr";
    std::string paswwrord_fn = "password.txt";
} typedef args;

unsigned short S[16] = {5,8,13,4,9,10,11,2,14,7,15,3,0,12,6,1};

args arguments_parse(int argc, char** argv);
void argument_check(args args, std::vector<unsigned char>& content, std::vector<unsigned char>& pass);
void print_help();
unsigned int get_filesize(std::string filename);
std::vector<unsigned char> get_content(std::string filename, int len=0);
std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass);
std::vector<unsigned char> decrypt_text(std::vector<unsigned char> encr, std::vector<unsigned char> pass);
std::vector<std::bitset<N>>
add_last_block(std::vector<std::bitset<N>> open_blocks, std::vector<unsigned char> last_block);
std::bitset<N> round(std::bitset<N> X, std::bitset<N> k);
void output_content(std::vector<unsigned char> close);

int main(int argc, char** argv) {
    args arguments = arguments_parse(argc, argv);


    std::vector<unsigned char> opentext;
    std::vector<unsigned char> closetext;
    std::vector<unsigned char> password;

    if (arguments.eflag) {
        argument_check(arguments, opentext, password);
        closetext = encrypt_text(opentext, password);
        output_content(closetext);
    }
    else {
        argument_check(arguments, closetext, password);
        opentext = decrypt_text(closetext, password);
        output_content(opentext);
    }

    return 0;
}

void output_content(std::vector<unsigned char> close) {
    std::ofstream file("encrypted.txt", std::ofstream::binary);
    file.write(std::string(close.begin(), close.end()).c_str(), close.size());
    file.close();
}


//bitset устанавливает в обратном порядке, то есть bitset[0] -- младший бит.
std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass) {
    std::vector<std::bitset<N>> open_blocks = std::vector<std::bitset<N>>();
    std::vector<std::bitset<N>> cipher_blocks = std::vector<std::bitset<N>>();
    unsigned long full_blocks = (open.size()-open.size()%blocklen_bytes)/blocklen_bytes;
    for (int i = 0; i<full_blocks; i++) {
        int ptr = i*blocklen_bytes;
        std::bitset<8> test(open[ptr]);
        //например, можно сделать цикл, который будет заполнять битсет
        unsigned long long block = ((open[ptr+3]<<24) + (open[ptr+2]<<16) + (open[ptr+1] << 8) + open[ptr+0]); //вот тут используется то, что длина блока равна 4. Хорошо бы сделать универсально.
        open_blocks.emplace_back(std::bitset<N>(block));
    }
    open_blocks = add_last_block(open_blocks, std::vector<unsigned char>(open.begin() + full_blocks*blocklen_bytes, open.end()));

    std::bitset<N> oddK((pass[0]<<24)+(pass[1]<<16)+(pass[2]<<8)+(pass[3]));
    std::bitset<N> evenK = ~oddK;

    for (std::bitset<N> X : open_blocks) {
        std::bitset<N> cipher_block = X;
        for (int i = 0; i < D; i++) {
            if (((i + 1) % 2) == 1) {
                cipher_block = round(cipher_block, oddK);
            }
            else {
                cipher_block = round(cipher_block, evenK);
            }
        }
        cipher_block ^= std::bitset<N>(0xff);
        cipher_blocks.push_back(cipher_block);
    }

    std::vector<unsigned char> toRet;
    for (std::bitset<N> cipher_block : cipher_blocks) {
//        std::cout << cipher_block.to_string() << " ( " << cipher_block.to_ulong() << " ) "  << " ";
        toRet.emplace_back((cipher_block.to_ulong()>>24) & 0xff);
        toRet.emplace_back((cipher_block.to_ulong()>>16) & 0xff);
        toRet.emplace_back((cipher_block.to_ulong()>>8) & 0xff);
        toRet.emplace_back((cipher_block.to_ulong()>>0) & 0xff);
    }
    std::cout << std::endl;
    return toRet;

}

std::bitset<N> round(std::bitset<N> X, std::bitset<N> k) {
    X ^= k;
    for (int i =0; i<N; i+=M) {
        unsigned long long elem = (X[i] + (X[i+1]<<1) + (X[i+2]<<2) + (X[i+3]<<3));
        elem = S[elem];
        X[i] = elem & 0b0001;
        X[i+1] = ((elem & 0b0010) >>1);
        X[i+2] = ((elem & 0b0100) >>2);
        X[i+3] = ((elem & 0b1000) >>3);
    }
    return X;
}

std::vector<std::bitset<N>>
add_last_block(std::vector<std::bitset<N>> open_blocks, std::vector<unsigned char> last_block) {
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
    std::vector<std::bitset<N>> result = open_blocks;
    result.emplace_back((full_block[3]<<24) + (full_block[2]<<16) + (full_block[1]<<8)+full_block[0]);
    result.emplace_back(last_block_size);
    return result;
}

void argument_check(args args, std::vector<unsigned char>& content, std::vector<unsigned char>& pass) {
    if (args.fflag) {
        content = get_content(args.opentext_fn);
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
    while ((c = getopt(argc, argv, ":hedf::p:P::")) != -1) {
        switch(c) {
            case 'h':{
                print_help();
                exit(0);
            }
            case 'e':{
                if (args.dflag) {
                    std::cerr << "Only encrypt OR decrypt" << std::endl;
                    exit(1);
                }
                args.eflag = true;
                break;
            }
            case 'd':{
                if (args.eflag) {
                    std::cerr << "Only encrypt OR decrypt" << std::endl;
                    exit(1);
                }
                args.dflag = true;
                break;
            }
            case 'f': {
                if (args.fflag) {
                    std::cerr << "Only one file by run" << std::endl;
                    exit(1);
                }
                args.fflag = true;
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
    if (!args.fflag) {
        args.fflag = true;
        args.opentext_fn = "opentext.txt";
    }
    if (!args.dflag && !args.eflag) {
        std::cerr << "Should use -e or -d";
        print_help();
        exit(1);
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
                "-P PASSWORD filename\n" <<
                "-e encrypt mode\n" <<
                "-d decrypt mode\n"
                "You should use -e either -d parameter\n"
    << std::endl;
}