/**
 * @file kuznechik.h
 * @brief Реализация блочного шифра "Кузнечик" (ГОСТ Р 34.12-2018)
 * @version 1.0
 * @date 2026
 * 
 * Данный файл содержит определение класса Kuznechik,
 * реализующего алгоритм блочного шифрования "Кузнечик"
 * в режиме гаммирования согласно ГОСТ Р 34.13-2018.
 */

#ifndef KUZNECHIK_H
#define KUZNECHIK_H

#include <cstdint>
#include <vector>
#include <string>

/** @def BLOCK_SIZE
 *  @brief Размер блока в байтах (128 бит = 16 байт) */
#define BLOCK_SIZE 16

/** @def KEY_SIZE
 *  @brief Размер ключа в байтах (256 бит = 32 байта) */
#define KEY_SIZE 32

/** @def ROUNDS
 *  @brief Количество раундов шифрования */
#define ROUNDS 10

/**
 * @class Kuznechik
 * @brief Класс для шифрования/расшифрования алгоритмом "Кузнечик"
 * 
 * Реализует блочный шифр по ГОСТ Р 34.12-2018 с размером блока 128 бит
 * и ключом 256 бит. Поддерживает режим гаммирования по ГОСТ Р 34.13-2018.
 * 
 * @example main.cpp
 * Пример использования:
 * @code
 * string key_str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
 * vector<uint8_t> key = hex_to_bytes(key_str);
 * Kuznechik cipher(key);
 * vector<uint8_t> plaintext = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
 * vector<uint8_t> ciphertext = cipher.encrypt_block(plaintext);
 * @endcode
 */
class Kuznechik {
public:
    /**
     * @brief Конструктор класса Kuznechik
     * @param key Ключ шифрования (32 байта)
     * @throw std::invalid_argument если длина ключа != 32
     */
    Kuznechik(const std::vector<uint8_t>& key);
    
    /**
     * @brief Шифрование одного 128-битного блока
     * @param block Открытый блок данных (16 байт)
     * @return Зашифрованный блок (16 байт)
     * @throw std::invalid_argument если размер блока != 16
     * 
     * Выполняет 10 раундов преобразований согласно ГОСТ Р 34.12-2018.
     * Последовательность: XOR с K1, затем 9 раундов (XOR, S, L),
     * финальный XOR с K10.
     */
    std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& block) const;
    
    /**
     * @brief Расшифрование одного 128-битного блока
     * @param block Зашифрованный блок данных (16 байт)
     * @return Расшифрованный блок (16 байт)
     * @throw std::invalid_argument если размер блока != 16
     * 
     * Выполняет обратные преобразования в обратном порядке.
     */
    std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& block) const;
    
    /**
     * @brief Шифрование одного 128-битного блока с выводом промежуточных результатов
     * @param block Открытый блок данных (16 байт)
     * @return Зашифрованный блок (16 байт)
     */
    std::vector<uint8_t> encrypt_block_debug(const std::vector<uint8_t>& block) const;
    /**
     * @brief Расшифрование одного 128-битного блока с выводом промежуточных результатов
     * @param block Зашифрованный блок данных (16 байт)
     * @return Расшифрованный блок (16 байт)
     */
    std::vector<uint8_t> decrypt_block_debug(const std::vector<uint8_t>& block) const;
    /**
     * @brief Шифрование данных в режиме гаммирования
     * @param plaintext Открытый текст (произвольной длины)
     * @param iv Начальное значение синхропосылки (64 бита)
     * @return Шифртекст
     * 
     
     * Режим гаммирования по ГОСТ Р 34.13-2018.
     * Для каждого блока счетчик инкрементируется и шифруется,
     * полученная гамма накладывается на открытый текст через XOR.
     * Последний блок может быть неполным.
     */
     
    std::vector<uint8_t> gamma_encrypt(const std::vector<uint8_t>& plaintext, uint64_t iv) const;
    
    /**
     * @brief Расшифрование данных в режиме гаммирования
     * @param ciphertext Шифртекст (произвольной длины)
     * @param iv Начальное значение синхропосылки (64 бита)
     * @return Расшифрованный текст
     * 
     * Расшифрование в режиме гаммирования идентично шифрованию,
     * так как операция XOR симметрична.
     */
    std::vector<uint8_t> gamma_decrypt(const std::vector<uint8_t>& ciphertext, uint64_t iv) const;

private:
    std::vector<std::vector<uint8_t>> round_keys; /**< Раундовые ключи (10 штук по 16 байт) */
    
    static const uint8_t S_BOX[256];     /**< S-бокс для нелинейного преобразования */
    static const uint8_t INV_S_BOX[256]; /**< Обратный S-бокс для расшифрования */
    static const uint8_t C[32][16];      /**< Константы для развертывания ключей */
    
    /**
     * @brief Развертывание ключей
     * @param key Исходный 256-битный ключ
     * 
     * Генерирует 10 раундовых ключей из основного ключа.
     * Использует итерационную схему с константами C_i.
     */
    void key_schedule(const std::vector<uint8_t>& key);
    
    /**
     * @brief XOR двух 16-байтовых блоков
     * @param state Блок, который изменяется (результат)
     * @param key Блок для XOR
     */
    void xor_blocks(std::vector<uint8_t>& state, const std::vector<uint8_t>& key) const;
    
    /**
     * @brief Нелинейное преобразование S
     * @param state 16-байтовый блок
     * 
     * Каждый байт заменяется по таблице S_BOX.
     */
    void s_transform(std::vector<uint8_t>& state) const;
    
    /**
     * @brief Обратное нелинейное преобразование InvS
     * @param state 16-байтовый блок
     */
    void inv_s_transform(std::vector<uint8_t>& state) const;
    
    /**
     * @brief Линейное преобразование L
     * @param state 16-байтовый блок
     * 
     * Выполняет умножение в поле Галуа GF(2^8) с фиксированной матрицей.
     * Обеспечивает диффузию данных.
     */
    void l_transform(std::vector<uint8_t>& state) const;
    
    /**
     * @brief Обратное линейное преобразование InvL
     * @param state 16-байтовый блок
     */
    void inv_l_transform(std::vector<uint8_t>& state) const;
    
    /**
     * @brief Умножение в поле Галуа GF(2^8)
     * @param a Первый множитель
     * @param b Второй множитель
     * @return Результат умножения
     * 
     * Использует неприводимый многочлен x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1 (0xC3).
     */
    uint8_t gf_mul(uint8_t a, uint8_t b) const;
};

/**
 * @brief Преобразование байтов в шестнадцатеричную строку
 * @param data Вектор байтов
 * @return Шестнадцатеричная строка
 */
std::string bytes_to_hex(const std::vector<uint8_t>& data);

/**
 * @brief Преобразование шестнадцатеричной строки в байты
 * @param hex Шестнадцатеричная строка (префикс 0x опционален)
 * @return Вектор байтов
 * @throw std::invalid_argument если строка содержит недопустимые символы
 */
std::vector<uint8_t> hex_to_bytes(const std::string& hex);

/**
 * @brief Вывод блока данных в консоль
 * @param label Метка для вывода
 * @param data Вектор байтов
 */
void print_block(const std::string& label, const std::vector<uint8_t>& data);

#endif
