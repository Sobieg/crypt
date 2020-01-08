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
    bool tflag = false;
    bool wflag = false;
    bool qflag = false;
    std::string opentext_fn = "opentext.txt";
    std::string encryoted_fn = "encrypted.txt";
    std::string password = "passerr";
    std::string paswwrord_fn = "password.txt";
    std::string target_fn = "target.txt";
    int R = 4;
} typedef args;

unsigned short S[16] =    {5,   8,  13, 4,  9,  10, 11, 2,  14, 7,  15, 3,  0,  12, 6,  1};
unsigned short revS[16] = {12,  15, 7,  11, 3,  0,  14, 9,  1,  4,  5,  6,  13, 2,  8,  10};

args arguments_parse(int argc, char** argv);
void argument_check(args args, std::vector<unsigned char>& content, std::vector<unsigned char>& pass);
void print_help();
unsigned int get_filesize(std::string filename);
std::vector<unsigned char> get_content(std::string filename, int len=0);
std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass);
std::vector<unsigned char> decrypt_text(std::vector<unsigned char> encr, std::vector<unsigned char> pass);
std::vector<std::bitset<N>>
add_last_block(std::vector<std::bitset<N>> open_blocks, std::vector<unsigned char> last_block);
unsigned long
get_last_block_size(std::vector<std::bitset<N>> closed_blocks);
std::bitset<N> round(std::bitset<N> X, std::bitset<N> k);
std::bitset<N> decrypt_round(std::bitset<N> Y, std::bitset<N> k);
void output_content(std::vector<unsigned char> content, std::string target);
unsigned short perm(unsigned short i);
unsigned short perm_rev(unsigned short i);

int main(int argc, char** argv) {
    args arguments = arguments_parse(argc, argv);


    std::vector<unsigned char> opentext;
    std::vector<unsigned char> closetext;
    std::vector<unsigned char> password;

    if (arguments.eflag) {
        argument_check(arguments, opentext, password);
        closetext = encrypt_text(opentext, password);
        output_content(closetext, "encrypted.txt");
    }
    else {
        argument_check(arguments, closetext, password);
        opentext = decrypt_text(closetext, password);
        output_content(opentext, "decrypted.txt");
    }

    return 0;
}

unsigned short perm(unsigned short i) {
    return (9*i+5)%32;
}

unsigned short perm_rev(unsigned short i) {
    return (25*i+3)%32;
}

void output_content(std::vector<unsigned char> content, std::string target) {
    std::ofstream file(target, std::ofstream::binary);
    file.write(std::string(content.begin(), content.end()).c_str(), content.size());
    file.close();
}


//bitset устанавливает в обратном порядке, то есть bitset[0] -- младший бит.
std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass) {
    std::vector<std::bitset<N>> open_blocks = std::vector<std::bitset<N>>();
    std::vector<std::bitset<N>> cipher_blocks = std::vector<std::bitset<N>>();
    unsigned long full_blocks = (open.size()-open.size()%blocklen_bytes)/blocklen_bytes;
    for (int i = 0; i<full_blocks; i++) {
        int ptr = i*blocklen_bytes;
//        std::bitset<8> test(open[ptr]);
        //например, можно сделать цикл, который будет заполнять битсет
        unsigned long long block = ((open[ptr+3]<<0) + (open[ptr+2]<<8) + (open[ptr+1] << 16) + (open[ptr+0]<<24)); //вот тут используется то, что длина блока равна 4. Хорошо бы сделать универсально.
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
//    std::cout << std::endl;
    return toRet;

}

std::vector<unsigned char> decrypt_text(std::vector<unsigned char> encr, std::vector<unsigned char> pass) {
    std::vector<std::bitset<N>> open_blocks = std::vector<std::bitset<N>>();
    std::vector<std::bitset<N>> cipher_blocks = std::vector<std::bitset<N>>();

    unsigned long full_blocks = encr.size()/blocklen_bytes;
    for (int i = 0; i<full_blocks; i++) {
        int ptr = i*blocklen_bytes;
        unsigned long long block = ((encr[ptr+3]) + (encr[ptr+2]<<8) + (encr[ptr+1] << 16) + (encr[ptr+0] << 24)); //вот тут используется то, что длина блока равна 4. Хорошо бы сделать универсально.
        cipher_blocks.emplace_back(std::bitset<N>(block));
    }

    std::bitset<N> evenK((pass[0]<<24)+(pass[1]<<16)+(pass[2]<<8)+(pass[3]));
    std::bitset<N> oddK = ~evenK;

    for (std::bitset<N> Y : cipher_blocks) {
        std::bitset<N> open_block = Y;
        open_block ^= std::bitset<N>(0xff);
        for (int i = 0; i < D; i++) {
            if (((i + 1) % 2) == 1) {
                open_block = decrypt_round(open_block, oddK);
            }
            else {
                open_block = decrypt_round(open_block, evenK);
            }
        }
        open_blocks.push_back(open_block);
    }
    unsigned long last_block_size = get_last_block_size(open_blocks);
    std::vector<unsigned char> toRet;

    for (auto it = open_blocks.begin(); it!= open_blocks.end()-2; it++) {
        //обработка не последнего блока
        toRet.emplace_back((it->to_ulong()>>24) & 0xff);
        toRet.emplace_back((it->to_ulong()>>16) & 0xff);
        toRet.emplace_back((it->to_ulong()>>8) & 0xff);
        toRet.emplace_back((it->to_ulong()>>0) & 0xff);
    }
    for (int i = 0; i<last_block_size; i++) {
        toRet.emplace_back(((open_blocks.end()-2)->to_ulong() >> (blocklen_bytes-i-1)*8) & 0xff);
    }

    return toRet;
}

std::bitset<N> decrypt_round(std::bitset<N> Y, std::bitset<N> k) {
    std::bitset<N> YY = Y;
    for (int i =0; i<N; i++) {
        Y[perm_rev(i)] = YY[i];
    }
    for (int i =0; i<N; i+=M) {
        unsigned long long elem = (Y[i] + (Y[i+1]<<1) + (Y[i+2]<<2) + (Y[i+3]<<3));
        elem = revS[elem];
        Y[i] = elem & 0b0001;
        Y[i+1] = ((elem & 0b0010) >>1);
        Y[i+2] = ((elem & 0b0100) >>2);
        Y[i+3] = ((elem & 0b1000) >>3);
    }
    Y ^= k;
    return Y;
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
    std::bitset<N> XX = X;
    for (int i = 0; i<N; i++) {
        X[perm(i)] = XX[i];
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
    result.emplace_back((full_block[3]<<0) + (full_block[2]<<8) + (full_block[1]<<16)+(full_block[0]<<24));
    result.emplace_back(last_block_size);
    return result;
}

unsigned long
get_last_block_size(std::vector<std::bitset<N>> closed_blocks) {
    unsigned long last_block_size = closed_blocks.back().to_ulong();
    closed_blocks.pop_back();
    return last_block_size;
}

void argument_check(args args, std::vector<unsigned char>& content, std::vector<unsigned char>& pass) {
    if (args.fflag && args.eflag) {
        content = get_content(args.opentext_fn);
    }
    else if (args.fflag && args.dflag) {
        content = get_content(args.encryoted_fn);
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
    while ((c = getopt(argc, argv, ":hedf::t:p:P::")) != -1) {
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
            case 't':{
                args.tflag = true;
                args.target_fn = optarg ? optarg : "target.txt";
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
                "-t TARGET filename\n"
                "-q R start error propagating test on R rounds\n"
                "-w find weak keys\n"
                "You should use -e, -d, -q or -w parameter\n"
    << std::endl;
}