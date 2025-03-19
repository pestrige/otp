export default class Otp {
    private readonly key;
    private readonly digit;
    private readonly ALPHABET;
    private readonly PAD;
    /**
     *
     * @param {string} key secret key string
     * @param {int} digit length of otp code
     */
    constructor(key: string, digit?: number);
    /**
     * generate an OTP base on SHA-1
     * @param {int} ttl time to live
     * @param {int} timestamp time shift
     */
    genOTP(ttl?: number, timestamp?: number): string;
    /**
     * verify an OTP code
     * @param {string} otp OTP code to verify
     * @param {int} ttl time to live
     */
    verify(otp: string, ttl?: number): boolean;
    private _truncat;
    private _factor2ByteText;
    /**
     * Кодирует строку s в Base32-формат.
     * @param s Исходная строка (ASCII/ANSI)
     * @returns Закодированная Base32-строка
     */
    private encode;
    /**
     * Декодирует Base32-строку s обратно в исходную (ASCII) строку.
     * @param s Base32-строка
     * @returns Декодированный результат
     */
    private decode;
}
