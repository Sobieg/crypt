#include <iostream>
#include <vector>
#include <fstream>
#include <map>
#include <unistd.h>
#include <bitset>
#include <thread>
#include <mutex>
#include <algorithm>
#include <random>

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
    bool bflag = false;
    std::string opentext_fn = "opentext.txt";
    std::string encryoted_fn = "encrypted.txt";
    std::string password = "passerr";
    std::string paswwrord_fn = "password.txt";
    std::string target_fn = "target.txt";
    int R = 4;
} typedef args;


unsigned short S[16] =    {4,   10,  9, 2,  13,  8, 0, 14,  6, 11,  1, 12,  7,  15, 5,  3};

std::mutex mut;


void print_help();
args arguments_parse(int argc, char** argv);
void argument_check(args args, std::vector<unsigned char>& content, std::vector<unsigned char>& pass);
std::vector<unsigned char> get_content(const std::string& filename, int len);
std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass);
std::vector<unsigned char> decrypt_text(std::vector<unsigned char> encr, std::vector<unsigned char> pass);
std::vector<std::bitset<N>>
add_last_block(std::vector<std::bitset<N>> open_blocks, std::vector<unsigned char> last_block);
unsigned long
get_last_block_size(std::vector<std::bitset<N>> closed_blocks);
void output_content(std::vector<unsigned char> content, const std::string& target);
void check_error_propagating(int rounds);
void find_weak_keys();
void weak_key_task(int a, std::vector<unsigned long> &keys);
std::string ucharvec_to_binary_string(std::vector<unsigned char>);
std::bitset<N> Feistel(std::bitset<N> open, std::bitset<N/2> key);
std::bitset<N> Lei_Messi(std::bitset<N> open, std::bitset<N/2> key);
std::bitset<N> tau(std::bitset<N> open);
std::bitset<N/2> sblock(std::bitset<N/2> X);
std::bitset<N/2> pblock(std::bitset<N/2> X);
unsigned short perm(unsigned short i);
std::bitset<N/2> spn(std::bitset<N/2> X, std::bitset<N/2> key);
void brute(std::vector<unsigned char> open, std::vector<unsigned char> encr);
void brute_task(std::vector<unsigned char> open, std::vector<unsigned char> encr, bool is_debug);



int main(int argc, char** argv) {
    args arguments = arguments_parse(argc, argv);

    std::vector<unsigned char> opentext;
    std::vector<unsigned char> closetext;
    std::vector<unsigned char> password;

    if (arguments.eflag) {
        argument_check(arguments, opentext, password);
        closetext = encrypt_text(opentext, password);
        output_content(closetext, arguments.tflag? arguments.target_fn : "encrypted.txt");
    }
    else if (arguments.dflag){
        argument_check(arguments, closetext, password);
        opentext = decrypt_text(closetext, password);
        output_content(opentext, arguments.tflag? arguments.target_fn : "decrypted.txt");
    }
    else if (arguments.qflag) {
        check_error_propagating(arguments.R);
    }
    else if (arguments.wflag) {
        find_weak_keys();
    }
    else if (arguments.bflag) {
        opentext = get_content(arguments.opentext_fn, 0);
        closetext = get_content(arguments.encryoted_fn, 0);
        brute(opentext, closetext);
    }
    return 0;
}

std::bitset<N/2> sblock(std::bitset<N/2> X) {
    for (int i = 0; i<N/2; i+=M) {
        unsigned long long elem = (X[i] + (X[i+1]<<1) + (X[i+2]<<2) + (X[i+3]<<3));
        elem = S[elem];
        X[i] = elem & 0b0001;
        X[i+1] = ((elem & 0b0010) >>1);
        X[i+2] = ((elem & 0b0100) >>2);
        X[i+3] = ((elem & 0b1000) >>3);
    }
    return X;
}

unsigned short perm(unsigned short i) {
    return (13*i+7)%16;
}

std::bitset<N/2> pblock(std::bitset<N/2> X) {
    std::bitset<N/2> XX = X;
    for (int i = 0; i<N/2; i++){
        X[perm(i)] = XX[i];
    }
    return X;
}

std::bitset<N/2> spn(std::bitset<N/2> X, std::bitset<N/2> key) {
    std::bitset<N/2> toRet = X^key;
    toRet = sblock(toRet);
    toRet = pblock(toRet);
    return toRet;
    return pblock(sblock(X^key));
}

std::bitset<N> Feistel(std::bitset<N> open, std::bitset<N/2> r_key) {
    std::string binblock = open.to_string('0','1');
    std::bitset<N/2> X_l(std::string(binblock.begin(), binblock.begin() + (binblock.size()/2)));
    std::bitset<N/2> X_r(std::string(binblock.begin()+(binblock.size()/2), binblock.end()));
#ifndef NDEBUG
    std::cout << "Feistel" << std::endl;
    std::cout << "0: " << binblock << std::endl;
    std::cout << "1: " << X_l.to_string('0','1') << " " << X_r.to_string('0','1') << std::endl;
#endif
#ifndef NDEBUG
    std::cout << std::bitset<N>(X_r.to_string('0','1') + (X_l ^ spn(X_r, r_key)).to_string('0','1')).to_string() << std::endl;
#endif
    return std::bitset<N>(X_r.to_string('0','1') + (X_l ^ spn(X_r, r_key)).to_string('0','1'));

}

std::bitset<N> Lei_Messi(std::bitset<N> open, std::bitset<N/2> r_key) {
    std::string binblock = open.to_string('0','1');
    std::bitset<N/2> X_l(std::string(binblock.begin(), binblock.begin() + (binblock.size()/2)));
    std::bitset<N/2> X_r(std::string(binblock.begin()+(binblock.size()/2), binblock.end()));
    //А я хз почему не работает, но там старший бит нормально не устанавливается. Скорее всего я криворук. fixme
#ifndef NDEBUG
    std::cout << "Lei-Messi: " << std::endl;
    std::cout << "0: " << binblock << std::endl;
    std::cout << "Strings: " << std::string(binblock.begin(), binblock.begin() + (binblock.size()/2)) << " " << std::string(binblock.begin()+(binblock.size()/2), binblock.end()) << std::endl;
    std::cout << "1: " << X_l.to_string('0','1') << " " << X_r.to_string('0','1') << std::endl;
#endif

#ifndef NDEBUG
    std::cout << std::bitset<N>((X_l^spn(X_l^X_r, r_key)).to_string('0','1') + (X_r ^ spn(X_l^X_r, r_key)).to_string('0','1')).to_string() << std::endl;
//    std::cout << toRet.to_string('0','1') << std::endl;
#endif
    return std::bitset<N>(((X_l^spn(X_l^X_r, r_key)).to_string('0','1') + (X_r ^ spn(X_l^X_r, r_key)).to_string('0','1')));
}

std::bitset<N> tau(std::bitset<N> open) {
    std::string openstr = open.to_string('0','1');
    std::bitset<N> toRet((std::string(openstr.begin() + openstr.size()/2, openstr.end())) +(std::string(openstr.begin(), openstr.begin()+openstr.size()/2)));
    return toRet;
}

std::vector<std::bitset<N>>
add_last_block(std::vector<std::bitset<N>> open_blocks, std::vector<unsigned char> last_block) {
    unsigned long long last_block_size = last_block.size();
    if (last_block_size == 0) {
        std::vector<std::bitset<N>> result = std::move(open_blocks);
        result.emplace_back(last_block_size);
        return result;
    }

    std::vector<unsigned char> full_block(blocklen_bytes);
    for (int i = 0; i<blocklen_bytes; i++) {
        if (i < last_block_size) {
            full_block[i] = last_block[i];
        }
        else {
            break;
        }
    }
    std::vector<std::bitset<N>> result = std::move(open_blocks);
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

void check_error_propagating(int rounds) {
    uint32_t randomKey = 0x1258927e;
    for (int i =0; i<N; i++) {
        bool flag = false;
        std::cout << "Checking " << i << "bit... ";
        std::string Kstr = std::bitset<N>(randomKey).to_string('0','1');
        std::bitset<N/2> K1(std::string(Kstr.begin(), Kstr.begin() + Kstr.size()/2));
        std::bitset<N/2> K2(std::string(Kstr.begin() + Kstr.size()/2, Kstr.end()));
        std::bitset<N> result(0x0);
        for (unsigned long j = 0; j<0xffffffff; j++) {
            std::bitset<N> left(j);
            std::bitset<N> right(j);
            left.set(i, false);
            right.set(i, true);
            for (int r = 0; r<rounds; r++){
                if (r < rounds/2+1) {
                    if (r%2) {
                        left = Feistel(left, K1);
                        right = Feistel(right, K1);
                    }
                    else {
                        left = Feistel(left, K2);
                        right = Feistel(right, K2);
                    }
                }
                else {
                    if (r%2) {
                        left = Lei_Messi(left, K1);
                        right = Lei_Messi(right, K1);
                    }
                    else {
                        left = Lei_Messi(left, K2);
                        right = Lei_Messi(right, K2);
                    }
                }
            }
            result |= left^right;
            if (result == std::bitset<N>(0xffffffff)) {
                std::cout << "error is propageted on " << std::hex << std::showbase << j << std::dec << std::endl;
                flag = true;
                break;
            }
        }
        if (!flag) {
            std::cout << "error is not propagated" << std::endl;
            break;
        }
    }
}
void find_weak_keys() {
    std::vector<std::thread*> threads;
    std::vector<unsigned long> keys;
    for (int a = 0; a<0xff; a+=64) {
        threads.emplace_back(new std::thread(weak_key_task, a, std::ref(keys)));
    }
    for (auto thr : threads) {
        thr->join();
        delete(thr);
    }
    std::cout << "There is no more weak keys" << std::endl;
    std::cout << "Founded " << keys.size() << "keys" << std::endl;
}

void weak_key_task(int a, std::vector<unsigned long> &keys) {
    std::vector<unsigned char> key(4, 0);
    std::vector<unsigned char> plain = {'p','l','a','i'};
    int aa = a+64;
    for (;a<aa; a++) {
        key[0] = a;
        for (int b = 0; b<0xff; b++) {
            key[1] = b;
            for (int c = 0; c < 0xff; c++) {
                key[2] = c;
                for (int d = 0; d < 0xff; d++) {
                    key[3] = d;
                    if (encrypt_text(encrypt_text(plain, key), key) == plain) {
                        mut.lock();
                        std::cout << "Found new weak key: " << std::hex << std::showbase
                                  << ((key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3]) << std::dec
                                  << std::endl;
                        keys.emplace_back((a << 24) + (b << 16) + (c << 8) + d);
                        mut.unlock();
                    }
                }
            }
        }
    }
}

void brute(std::vector<unsigned char> open, std::vector<unsigned char> encr) {
    time_t start, end;
    time(&start);
#if !defined(NDEBUG)
    brute_task(open, encr, true);
#else
    brute_task(open, encr, false);
#endif
    time(&end);
    std::cout << "Time elapsed: " << difftime(end, start) << "s" << std::endl;
}

void brute_task(std::vector<unsigned char> open, std::vector<unsigned char> encr, bool is_debug) {
    std::vector<unsigned char> guess;
    std::vector<unsigned char> key(4,0);
    if (is_debug) {
        for (int a ='q'; a<0xff; a++){
            key[0] = (unsigned char) a;
            for (int b = 'w'; b<0xff; b++) {
                key[1] = (unsigned char) b;
                for (int c = 'e'; c<0xff; c++) {
                    key[2] = (unsigned char) c;
                    for (int d = 'r'-10; d<0xff; d++) {
                        key[3] = (unsigned char) d;
                        guess = decrypt_text(encr, key);
                        if (guess == open) {
                            std::cout << "guessed, pass is " << std::string(key.begin(), key.end()) << std::endl;
                            std::cout << "Text is :\n" << std::string(guess.begin(), guess.end()) << std::endl;
                            return;
                        }
                    }
                }
            }
        }
    }
    else {
        for (int a =0; a<0xff; a++){
            key[0] = (unsigned char) a;
            for (int b = 0; b<0xff; b++) {
                key[1] = (unsigned char) b;
                for (int c = 0; c<0xff; c++) {
                    key[2] = (unsigned char) c;
                    for (int d = 0; d<0xff; d++) {
                        key[3] = (unsigned char) d;
//                        std::cout << "Try key 0x" << std::hex << a << b << c << d << std::dec<< std::endl;
                        guess = decrypt_text(encr, key);
                        if (guess == open) {
                            std::cout << "guessed, pass is 0x" << std::hex << a << b << c << d << std::endl << std::endl;
                            std::cout << "Text is :\n" << std::string(guess.begin(), guess.end()) << std::endl;
                            return;
                        }
                    }
                }
            }
        }
    }
}


std::string ucharvec_to_binary_string(std::vector<unsigned char> text) {
    std::string bin;
    for (auto c  = text.rbegin(); c!= text.rend(); c++) {
        int b = 0;
        auto val = (unsigned int) *c;
        while(val != 0){
            bin.push_back(val%2 ? '1' : '0');
            val /= 2;
            b++;
        }
        while(b++!=8) {
            bin.push_back('0');
        }
    }
    std::reverse(bin.begin(), bin.end());
    return bin;
}

std::vector<unsigned char> encrypt_text(std::vector<unsigned char> open, std::vector<unsigned char> pass) {
    std::vector<std::bitset<N>> open_blocks = std::vector<std::bitset<N>>();
    std::vector<std::bitset<N>> cipher_blocks = std::vector<std::bitset<N>>();
    unsigned long full_blocks = (open.size()-open.size()%blocklen_bytes)/blocklen_bytes;
    for (int i = 0; i<full_blocks; i++) {
        int ptr = i*blocklen_bytes;
        unsigned long long block = 0;
        for (int b = 0; b<blocklen_bytes; b++) {
            block += ((unsigned long)open[ptr+b] << (blocklen_bytes-1-b)*8);
        }
        open_blocks.emplace_back(std::bitset<N>(block));
    }
    open_blocks = add_last_block(open_blocks, std::vector<unsigned char>(open.begin() + full_blocks*blocklen_bytes, open.end()));

    std::string binpass = ucharvec_to_binary_string(pass);
    std::bitset<N/2> K1(std::string(binpass.begin(), binpass.begin() + (binpass.size()/2)));
    std::bitset<N/2> K2 (std::string(binpass.begin() + (binpass.size()/2), binpass.end()));

    for (std::bitset<N> X : open_blocks) {
        X = Feistel(X, K1);
        X = Feistel(X, K2);
//        X = Feistel(X, K1);
//        X = Feistel(X, K2);
        X = Lei_Messi(X, K1);
        X = Lei_Messi(X, K2);
        cipher_blocks.emplace_back(X);
    }

    std::vector<unsigned char> toRet;
    for (std::bitset<N> cipher_block : cipher_blocks) {
        toRet.emplace_back((cipher_block.to_ulong()>>24) & 0xff);
        toRet.emplace_back((cipher_block.to_ulong()>>16) & 0xff);
        toRet.emplace_back((cipher_block.to_ulong()>>8) & 0xff);
        toRet.emplace_back((cipher_block.to_ulong()>>0) & 0xff);
    }
    return toRet;
}

std::vector<unsigned char> decrypt_text(std::vector<unsigned char> encr, std::vector<unsigned char> pass) {
    std::vector<std::bitset<N>> open_blocks = std::vector<std::bitset<N>>();
    std::vector<std::bitset<N>> cipher_blocks = std::vector<std::bitset<N>>();
    unsigned long full_blocks = encr.size()/blocklen_bytes;
    for (int i = 0; i<full_blocks; i++) {
        int ptr = i*blocklen_bytes;
        unsigned long long block = 0;
        for (int b = 0; b<blocklen_bytes; b++) {
            block += ((unsigned long)encr[ptr+b] << (blocklen_bytes-1-b)*8);
        }
        cipher_blocks.emplace_back(std::bitset<N>(block));
    }

    std::string binpass = ucharvec_to_binary_string(pass);
    std::bitset<N/2> K1(std::string(binpass.begin(), binpass.begin() + (binpass.size()/2)));
    std::bitset<N/2> K2 (std::string(binpass.begin() + (binpass.size()/2), binpass.end()));

    for (std::bitset<N> X : cipher_blocks) {
        X = Lei_Messi(X, K2);
        X = Lei_Messi(X, K1);
        X = tau(X);
        X = Feistel(X, K2);
        X = Feistel(X, K1);
//        X = Feistel(X, K2);
//        X = Feistel(X, K1);
        X = tau(X);
        open_blocks.emplace_back(X);
    }

    unsigned long last_block_size = get_last_block_size(open_blocks);
    if (last_block_size > 4 ) {
#if !defined(NDEBUG)
        //std::cerr << "Error while decrypting: last_block_size more than 4: " << last_block_size << " " << std::hex << std::showbase<< last_block_size << std::dec << std::endl;
#endif
        last_block_size = 0;
    }

    std::vector<unsigned char> toRet;
    for (auto it = open_blocks.begin(); it!= open_blocks.end()- (last_block_size ? 2 : 1) ; it++) {
        for (int b = 0; b<blocklen_bytes; b++) {
            toRet.emplace_back((it->to_ulong() >> ((blocklen_bytes-1-b)*8)) & 0xff);
        }
    }
    for (int i = 0; i<last_block_size; i++) {
        toRet.emplace_back(((open_blocks.end()-2)->to_ulong() >> ((blocklen_bytes-i-1)*8)) & 0xff);
    }
    return toRet;
}

void output_content(std::vector<unsigned char> content, const std::string& target) {
    std::ofstream file(target, std::ofstream::binary);
    file.write(std::string(content.begin(), content.end()).c_str(), content.size());
    file.close();
}

args arguments_parse(int argc, char** argv) {
    args args;
    int c;
    while ((c = getopt(argc, argv, ":hedbq:wf::t:p:P::")) != -1) {
        switch(c) {
            case 'h':{
                print_help();
                exit(0);
            }
            case 'e':{
                if (args.dflag or args.qflag or args.wflag or args.bflag) {
                    std::cerr << "Only one task by run" << std::endl;
                    exit(1);
                }
                args.eflag = true;
                break;
            }
            case 'd':{
                if (args.eflag or args.wflag or args.qflag or args.bflag) {
                    std::cerr << "Only one task by run" << std::endl;
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
                break;
            }
            case 'q': {
                if (args.dflag or args.eflag or args.wflag or args.bflag) {
                    std::cerr << "Only one task by run" << std::endl;
                    exit(1);
                }
                args.qflag = true;
                if (optarg) {
                    for (char *c = optarg; *c != 0; c++) {
                        if (!isnumber(*c)) {
                            std::cerr << "Error on -q R" << std::endl;
                            exit(1);
                        }
                    }
                    args.R = atoi(optarg);
                }
                else {
                    args.R = 4;
                }
                break;
            }
            case 'w':{
                if (args.qflag or args.dflag or args.eflag or args.bflag) {
                    std::cerr << "Only one task by run" << std::endl;
                    exit(1);
                }
                args.wflag = true;
                break;
            }
            case 'b': {
                if (args.qflag or args.dflag or args.eflag or args.wflag){
                    std::cerr << "Only one task by run" << std::endl;
                    exit(1);
                }
                args.bflag = true;
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
    if (!args.dflag && !args.eflag && !args.wflag && !args.qflag && !args.bflag) {
        std::cerr << "Should use -e or -d or -w or -q";
        print_help();
        exit(1);
    }
    return args;
}

void argument_check(args args, std::vector<unsigned char>& content, std::vector<unsigned char>& pass) {
    if (args.fflag && args.eflag) {
        content = get_content(args.opentext_fn, 0);
    }
    else if (args.fflag && args.dflag) {
        content = get_content(args.encryoted_fn, 0);
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

unsigned int get_filesize(const std::string& filename){
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

std::vector<unsigned char> get_content(const std::string& filename, int len = 0){
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
              "-b brute force pass\n"
              "You should use -e, -d, -q or -w parameter\n"
              << std::endl;
}