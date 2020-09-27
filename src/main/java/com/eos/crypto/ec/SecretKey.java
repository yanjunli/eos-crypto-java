/* 
 * Copyright (C) 2018 Aayush Atharva
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.eos.crypto.ec;

import com.eos.crypto.exception.AtomicCryptoException;
import com.eos.crypto.util.Base58;

import java.security.SecureRandom;

/**
 * Secret Key For Cryptography
 *
 * @author Aayush Atharva
 */
public class SecretKey {

    private byte[] key;

    /**
     * Create A Secret Key From 32 Byte (256 bit) Key Material
     *
     * @param key A Secret Key
     */
    public SecretKey(byte[] key) {
        assert key.length == 32;
        this.key = key.clone();
    }

    /**
     * Generate A New 32 Byte (256 Bit) Secret Key With SecureRandom Chosen By System
     *
     * @return A Secret Key
     * @throws AtomicCryptoException When SecureRandom Fails To Initialize
     */
    public static SecretKey generate() throws AtomicCryptoException {
        byte[] key = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return new SecretKey(key);
    }

    /**
     * Generate A New 32 Byte (256 Bit) Secret Key With Defined SecureRandom
     * 
     * @param secureRandom SecureRandom
     * @return A Secret Key
     * @throws AtomicCryptoException When SecureRandom Fails To Initialize
     */
    public static SecretKey generate(SecureRandom secureRandom) throws AtomicCryptoException {
        byte[] key = new byte[32];
        SecureRandom random = secureRandom;
        random.nextBytes(key);
        return new SecretKey(key);
    }

    /**
     * Retrieve The Secret Key
     *
     * @return The 32 Byte (256 Bit) Secret Key
     */
    public byte[] getBytes() {
        return key.clone();
    }

    /**
     * Get Secret Key In Base64 Encoding
     *
     * @return Base58 Encoded Secret Key
     */
    public String getKeyAsBase58() {
        return Base58.encode(getBytes());
    }

}
