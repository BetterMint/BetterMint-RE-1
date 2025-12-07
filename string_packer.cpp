#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <random>

std::string generate_var_name() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    int len = 3 + (gen() % 5);
    std::string name;
    name += chars[dis(gen)];
    for (int i = 1; i < len; i++) {
        name += chars[dis(gen)];
    }
    return name;
}

std::string pack_string_data(const std::string& str, uint8_t& key) {
    key = static_cast<uint8_t>(rand() % 256);
    std::vector<uint8_t> enc;
    enc.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        uint8_t b = static_cast<uint8_t>(str[i]);
        uint8_t k = static_cast<uint8_t>(key + static_cast<unsigned int>(i * 13u));
        enc.push_back(static_cast<uint8_t>(b ^ k));
    }
    std::ostringstream oss;
    for (size_t i = 0; i < enc.size(); ++i) {
        if (i > 0) oss << ",";
        if (i % 12 == 0 && i > 0) oss << "\n    ";
        else if (i > 0) oss << " ";
        oss << "0x" << std::hex;
        unsigned int v = enc[i];
        if (v < 0x10u) oss << "0";
        oss << v << std::dec;
    }
    return oss.str();
}

bool should_skip_string(const std::string& content, size_t pos) {
    size_t lineStart = content.rfind('\n', pos);
    if (lineStart == std::string::npos) lineStart = 0;
    else lineStart++;
    std::string line = content.substr(lineStart, pos - lineStart);
    if (line.find("#pragma") != std::string::npos) return true;
    if (line.find("static const uint8_t") != std::string::npos) return true;
    if (line.find("STR_") != std::string::npos) return true;
    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: string_packer.exe <input.cpp> [output.cpp]\n";
        std::cout << "This tool automatically packs all string literals in a C++ file.\n";
        return 1;
    }
    
    std::ifstream inFile(argv[1]);
    if (!inFile) {
        std::cerr << "Error: Cannot open input file " << argv[1] << std::endl;
        return 1;
    }
    
    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    std::vector<std::pair<std::string, std::string>> replacements;
    std::vector<std::string> packed_declarations;
    
    std::regex strRegex("\"([^\"]*(\\\\.[^\"]*)*)\"");
    std::sregex_iterator iter(content.begin(), content.end(), strRegex);
    std::sregex_iterator end;
    
    std::string varName = "d1_unpack";
    
    for (; iter != end; ++iter) {
        std::smatch match = *iter;
        std::string fullMatch = match.str(0);
        size_t matchPos = match.position(0);
        
        if (should_skip_string(content, matchPos)) {
            continue;
        }
        
        std::string strContent = match.str(1);
        
        std::string unpacked;
        for (size_t i = 0; i < strContent.length(); ++i) {
            if (strContent[i] == '\\' && i + 1 < strContent.length()) {
                if (strContent[i + 1] == 'n') {
                    unpacked += '\n';
                    i++;
                } else if (strContent[i + 1] == 't') {
                    unpacked += '\t';
                    i++;
                } else if (strContent[i + 1] == '\\') {
                    unpacked += '\\';
                    i++;
                } else if (strContent[i + 1] == '"') {
                    unpacked += '"';
                    i++;
                } else {
                    unpacked += strContent[i];
                }
            } else {
                unpacked += strContent[i];
            }
        }
        
        if (unpacked.length() > 0 && unpacked.length() < 200) {
            uint8_t key;
            std::string packedData = pack_string_data(unpacked, key);
            std::string varNameStr = "STR_" + generate_var_name();
            
            std::ostringstream decl;
            decl << "static const uint8_t " << varNameStr << "[] = {\n    " << packedData << "\n};";
            packed_declarations.push_back(decl.str());
            
            std::ostringstream unpackCall;
            unpackCall << varName << "(" << varNameStr << ", sizeof(" << varNameStr << "), 0x" 
                       << std::hex << static_cast<unsigned int>(key) << std::dec << "u)";
            
            replacements.push_back({fullMatch, unpackCall.str()});
        }
    }
    
    std::string output = content;
    for (auto it = replacements.rbegin(); it != replacements.rend(); ++it) {
        size_t pos = 0;
        while ((pos = output.find(it->first, pos)) != std::string::npos) {
            if (!should_skip_string(output, pos)) {
                std::string replacement = it->second;
                
                size_t beforePos = (pos > 0) ? pos - 1 : 0;
                size_t afterPos = pos + it->first.length();
                
                bool needsCStr = false;
                
                if (afterPos < output.length()) {
                    char after = output[afterPos];
                    if (after == ')' || after == ',' || after == ';') {
                        needsCStr = true;
                    }
                }
                
                if (beforePos < output.length() && pos > 0) {
                    char before = output[beforePos];
                    if (before == '(' || before == ',') {
                        needsCStr = true;
                    }
                }
                
                size_t lineStart = output.rfind('\n', pos);
                if (lineStart == std::string::npos) lineStart = 0;
                else lineStart++;
                std::string lineBefore = output.substr(lineStart, pos - lineStart);
                if (lineBefore.find("const char*") != std::string::npos ||
                    lineBefore.find("LPCSTR") != std::string::npos ||
                    lineBefore.find("LPSTR") != std::string::npos ||
                    lineBefore.find("char*") != std::string::npos) {
                    needsCStr = true;
                }
                
                if (needsCStr) {
                    replacement = "(" + replacement + ").c_str()";
                }
                
                output.replace(pos, it->first.length(), replacement);
                pos += replacement.length();
            } else {
                pos += it->first.length();
            }
        }
    }
    
    size_t insertPos = 0;
    size_t searchPos = 0;
    size_t lastPreprocLine = 0;
    
    while (searchPos < output.length()) {
        size_t hashPos = output.find('#', searchPos);
        if (hashPos == std::string::npos) break;
        
        size_t lineStart = output.rfind('\n', hashPos);
        if (lineStart == std::string::npos) lineStart = 0;
        else lineStart++;
        
        size_t lineEnd = output.find('\n', hashPos);
        if (lineEnd == std::string::npos) {
            lastPreprocLine = output.length();
            break;
        }
        
        std::string line = output.substr(lineStart, lineEnd - lineStart);
        if (line.find("#include") != std::string::npos ||
            line.find("#pragma") != std::string::npos ||
            line.find("#ifdef") != std::string::npos ||
            line.find("#ifndef") != std::string::npos ||
            line.find("#define") != std::string::npos ||
            line.find("#endif") != std::string::npos) {
            lastPreprocLine = lineEnd + 1;
            searchPos = lineEnd + 1;
        } else {
            break;
        }
    }
    
    if (lastPreprocLine > 0 && !packed_declarations.empty()) {
        while (lastPreprocLine < output.length() && 
               (output[lastPreprocLine] == ' ' || output[lastPreprocLine] == '\t' || 
                output[lastPreprocLine] == '\n' || output[lastPreprocLine] == '\r')) {
            lastPreprocLine++;
        }
        std::string packedDecls = "\n";
        for (const auto& decl : packed_declarations) {
            packedDecls += decl + "\n";
        }
        output.insert(lastPreprocLine, packedDecls);
    }
    
    std::string outFileName = (argc >= 3) ? argv[2] : std::string(argv[1]) + ".packed";
    std::ofstream outFile(outFileName);
    if (!outFile) {
        std::cerr << "Error: Cannot create output file " << outFileName << std::endl;
        return 1;
    }
    
    outFile << output;
    outFile.close();
    
    std::cout << "Packed " << replacements.size() << " strings to " << outFileName << std::endl;
    return 0;
}
