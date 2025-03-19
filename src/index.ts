import jsSHA from 'jssha';

/* eslint-disable no-bitwise */
export default class Otp {
	private readonly ALPHABET = 'AbcDeFghijKlmnOpQrstUvWxyZ234567';
	private readonly PAD = '';

	/**
	 *
	 * @param {string} key secret key string
	 * @param {int} digit length of otp code
	 */
	constructor(private readonly key: string, private readonly digit: number = 6) {
		this.key = key.replace(/[^a-zA-Z2-7]/g, '');
		this.digit = digit;
	}

	/**
	 * generate an OTP base on SHA-1
	 * @param {int} ttl time to live
	 * @param {int} timestamp time shift
	 */
	public genOTP(ttl: number = 30, timestamp?: number) {
		const movingFactor = Math.floor((timestamp ?? Date.now() / 1000) / ttl);
		const hmacSha = new jsSHA('SHA-1', 'BYTES');
		hmacSha.setHMACKey(this.key, 'BYTES');

		const factorByte = this._factor2ByteText(movingFactor);
		hmacSha.update(factorByte);

		const hmac_result = hmacSha.getHMAC('BYTES');
		const code = this._truncat(hmac_result);
		return this.encode(code);
	}

	/**
	 * verify an OTP code
	 * @param {string} otp OTP code to verify
	 * @param {int} ttl time to live
	 */
	public verify(otp: string, ttl: number = 30) {
		return otp === this.genOTP(ttl);
	}

	private _truncat(hmac_result: string) {
		const offset = hmac_result[19].charCodeAt(0) & 0xf;
		const bin_code =
		 ((hmac_result[offset].charCodeAt(0) & 0x7f) << 24) |
		 ((hmac_result[offset + 1].charCodeAt(0) & 0xff) << 16) |
		 ((hmac_result[offset + 2].charCodeAt(0) & 0xff) << 8) |
		 (hmac_result[offset + 3].charCodeAt(0) & 0xff);
		let otp = (bin_code % 10 ** this.digit).toString();
		while (otp.length < this.digit) {
			otp = '0' + otp;
		}
		return otp;
	}

	private _factor2ByteText(movingFactor: number) {
		const text = new Array(8);
		for (let i = text.length - 1; i >= 0; i--) {
			text[i] = String.fromCharCode(movingFactor & 0xff);
			movingFactor >>= 8;
		}
		return text.join('');
	}

	/**
	 * Кодирует строку s в Base32-формат.
	 * @param s Исходная строка (ASCII/ANSI)
	 * @returns Закодированная Base32-строка
	 */
	private encode(s: string): string {
		const a = this.ALPHABET;
		const pad = this.PAD;
		const len = s.length;

		let o = ''; // результат
		let w = 0; // word
		let c = 0; // charCode
		let r = 0; // remainder (остаток)
		let sh = 0; // shift

		for (let i = 0; i < len; i += 5) {
			// Берём очередной символ
			c = s.charCodeAt(i);
			// Маска верхних 5 бит: 0xf8 = 11111000₂
			w = 0xf8 & c;
			o += a.charAt(w >> 3);
			r = 0x07 & c;
			sh = 2;

			// Следующий символ (i+1)
			if (i + 1 < len) {
				c = s.charCodeAt(i + 1);
				// Маска верхних 2 бит: 0xc0 = 11000000₂
				w = 0xc0 & c;
				o += a.charAt((r << 2) + (w >> 6));
				o += a.charAt((0x3e & c) >> 1);
				r = c & 0x01; // 0b00000001
				sh = 4;
			}

			// Следующий символ (i+2)
			if (i + 2 < len) {
				c = s.charCodeAt(i + 2);
				// Маска верхних 4 бит: 0xf0 = 11110000₂
				w = 0xf0 & c;
				o += a.charAt((r << 4) + (w >> 4));
				r = 0x0f & c; // 0b00001111
				sh = 1;
			}

			// Следующий символ (i+3)
			if (i + 3 < len) {
				c = s.charCodeAt(i + 3);
				// Маска верхнего 1 бита: 0x80 = 10000000₂
				w = 0x80 & c;
				o += a.charAt((r << 1) + (w >> 7));
				o += a.charAt((0x7c & c) >> 2);
				r = 0x03 & c; // 0b00000011
				sh = 3;
			}

			// Следующий символ (i+4)
			if (i + 4 < len) {
				c = s.charCodeAt(i + 4);
				// Маска верхних 3 бит: 0xe0 = 11100000₂
				w = 0xe0 & c;
				o += a.charAt((r << 3) + (w >> 5));
				o += a.charAt(0x1f & c);
				r = 0;
				sh = 0;
			}
		}

		// Если что-то осталось в r — добавляем
		if (sh !== 0) {
			o += a.charAt(r << sh);
		}

		// Подсчитываем, нужно ли добавлять "паддинг"
		// (в исходном коде pad = "", можно отключить полностью)
		const padlen = 8 - (o.length % 8);
		// Если кратно 8 — ничего не добавляем
		if (padlen === 8) {
			return o;
		}
		// Варианты добавления паддинга
		if (padlen === 1) {
			return o + pad; // обычно = "="
		}
		if (padlen === 3) {
			return o + pad + pad + pad;
		}
		if (padlen === 4) {
			return o + pad + pad + pad + pad;
		}
		if (padlen === 6) {
			return o + pad + pad + pad + pad + pad + pad;
		}

		return o;
	}

	/**
	 * Декодирует Base32-строку s обратно в исходную (ASCII) строку.
	 * @param s Base32-строка
	 * @returns Декодированный результат
	 */
	private decode(s: string): string {
		const base32Chars = this.ALPHABET;
		let binaryString = '';
		let output = '';

		// Превращаем каждый Base32-символ в 5-битную двоичную последовательность
		for (const char of s) {
			const index = base32Chars.indexOf(char);
			if (index !== -1) {
				// Формируем 5-битную подстроку (дополняем нулями слева до 5 бит)
				binaryString += index.toString(2).padStart(5, '0');
			}
		}

		// Превращаем двоичную строку в байты (по 8 бит) и далее в символы
		for (let i = 0; i < binaryString.length; i += 8) {
			const byteBits = binaryString.substr(i, 8);
			// Если финальный блок < 8 бит, просто игнорируем
			if (byteBits.length === 8) {
				const code = parseInt(byteBits, 2);
				output += String.fromCharCode(code);
			}
		}

		return output;
	}
}
