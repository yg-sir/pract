#include "../include/kuznechik.h"
#include <iostream>
#include <limits>
#include <iomanip>

using namespace std;

int main() {
    
    string key_str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
    vector<uint8_t> key = hex_to_bytes(key_str);
    Kuznechik cipher(key);
    
    int mode;
    cout << "Выберите режим работы:" << endl;
    cout << "1. Тестовый пример (фиксированные данные)" << endl;
    cout << "2. Ввод своих данных" << endl;
    cout << "Ваш выбор: ";
    cin >> mode;
    cout << endl;
    
    if (mode == 1) {
        cout << "--- Тестовый пример (блочное шифрование) ---" << endl;
        
        vector<uint8_t> plaintext = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
        print_block("Исходные данные", plaintext);
        cout << endl;
        
        // Использование функции с выводом промежуточных результатов
        vector<uint8_t> ciphertext = cipher.encrypt_block_debug(plaintext);
        
        cout << endl;
        print_block("Шифртекст", ciphertext);
        cout << "Ожидаемый шифртекст: 0x7f679d90bebc24305a468d42b9d4edcd" << endl;
        
       if (bytes_to_hex(ciphertext) == "7f679d90bebc24305a468d42b9d4edcd") {
            cout << "√ ШИФРТЕКСТ СОВПАДАЕТ с эталоном!" << endl;
        } else {
            cout << "× ШИФРТЕКСТ НЕ СОВПАДАЕТ с эталоном!" << endl;
        }
        
        cout << "\n--- Процесс расшифрования ---" << endl;
        // Используем новую функцию расшифрования с выводом
        vector<uint8_t> decrypted = cipher.decrypt_block_debug(ciphertext);
        
        cout << endl;
        print_block("Расшифрованный текст", decrypted);
        
        if (decrypted == plaintext) {
            cout << "√ Расшифрование выполнено корректно!" << endl;
        } else {
            cout << "× Ошибка расшифрования!" << endl;
        }
        
        cout << "\n--- Тестовый пример (режим гаммирования) ---" << endl;
        
        // Многоблочный контрольный пример для гаммирования (32 байта / 2 блока)
        string gamma_pt_hex = "1122334455667700ffeeddccbbaa998800112233445566778899aabbccddeeff";
        vector<uint8_t> gamma_data = hex_to_bytes(gamma_pt_hex);
        uint64_t iv = 0x1234567890abcdef;
        
        cout << "Синхропосылка (IV): 0x" << hex << iv << dec << endl;
        print_block("Исходный текст", gamma_data);
        
        vector<uint8_t> gamma_cipher = cipher.gamma_encrypt(gamma_data, iv);
        print_block("Зашифровано (Гаммирование)", gamma_cipher);
        
        vector<uint8_t> gamma_decrypted = cipher.gamma_decrypt(gamma_cipher, iv);
        print_block("Расшифровано (Гаммирование)", gamma_decrypted);
        
        if (gamma_decrypted == gamma_data) {
            cout << "√ Гаммирование выполнено корректно!" << endl;
        } else {
            cout << "× Ошибка гаммирования!" << endl;
        }
        
    } else if (mode == 2) {
        cout << "--- Ввод своих данных ---" << endl;
        string input;
        cout << "Введите открытый текст (128 бит, 16 байт в hex): ";
        cin >> input;
        
        if (input.length() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
            input = input.substr(2);
        }
        
        vector<uint8_t> plaintext = hex_to_bytes(input);
        if (plaintext.size() != 16) {
            cout << "Ошибка: требуется ровно 16 байт (32 hex символа)" << endl;
            return 1;
        }
        
        print_block("Исходные данные", plaintext);
        
        vector<uint8_t> ciphertext = cipher.encrypt_block(plaintext);
        print_block("Шифртекст", ciphertext);
        
        vector<uint8_t> decrypted = cipher.decrypt_block(ciphertext);
        print_block("Расшифрованный текст", decrypted);
        
        if (decrypted == plaintext) {
            cout << "\n√ Шифрование и расшифрование выполнены корректно!" << endl;
        } else {
            cout << "\n× Ошибка: расшифрованный текст не совпадает с исходным!" << endl;
        }
    } else {
        cout << "Неверный выбор!" << endl;
        return 1;
    }
    
    cout << "\n===========================================" << endl;
    return 0;
}
