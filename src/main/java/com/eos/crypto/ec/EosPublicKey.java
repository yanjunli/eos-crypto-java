/*
 * Copyright (c) 2017-2018 PlayerOne.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.eos.crypto.ec;

import com.eos.crypto.digest.Ripemd160;
import com.eos.crypto.util.Arrays;
import com.eos.crypto.util.BitUtils;
import com.eos.crypto.util.RefValue;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.*;


/**
 */

public class EosPublicKey implements PublicKey {
    private static final String LEGACY_PREFIX = "EOS";
    private static final String PREFIX = "PUB";
    private final long mCheck;
    private final CurveParam mCurveParam;
    private final byte[] mData;

    public String getAlgorithm() {
        return EosPrivateKey.parameterSpec;
    }

    public String getFormat() {
        return "EOS ";
    }

    public byte[] getEncoded() {
        return getEcPoint().getEncoded(false);
    }

    public EcPoint getEcPoint(){
        return mCurveParam.getCurve().decodePoint(mData);
    }

    public static class IllegalEosPubkeyFormatException extends IllegalArgumentException {
        public IllegalEosPubkeyFormatException(String pubkeyStr) {
            super("invalid eos public key : " + pubkeyStr);
        }
    }

    public EosPublicKey( byte[] data ){
        this( data, EcTools.getCurveParam( EosPrivateKey.curveParam));
    }

    public EosPublicKey( byte[] data, CurveParam curveParam ){
        mData = Arrays.copyOfRange(data,0,  Math.min(data.length, 33));
        mCurveParam = curveParam;
        mCheck= BitUtils.uint32ToLong( Ripemd160.from( mData, 0, mData.length).bytes(), 0 );
    }

    public EosPublicKey(String base58Str) {
        RefValue<Long> checksumRef = new RefValue<Long>();

        String[] parts = EosEcUtil.safeSplitEosCryptoString( base58Str );
        if ( base58Str.startsWith(LEGACY_PREFIX) ) {
            if ( parts.length == 1 ){
                mCurveParam = EcTools.getCurveParam( EosPrivateKey.curveParam);
                mData = EosEcUtil.getBytesIfMatchedRipemd160( base58Str.substring( LEGACY_PREFIX.length()), null, checksumRef);
            }
            else {
                throw new IllegalEosPubkeyFormatException( base58Str );
            }
        }
        else {
            if ( parts.length < 3 ) {
                throw new IllegalEosPubkeyFormatException( base58Str );
            }

            // [0]: prefix, [1]: curve type, [2]: data
            if (!PREFIX.equals( parts[0]) ){
                throw new IllegalEosPubkeyFormatException( base58Str );
            }

            mCurveParam = EosEcUtil.getCurveParamFrom( parts[1]);
            mData = EosEcUtil.getBytesIfMatchedRipemd160( parts[2], parts[1], checksumRef);
        }

        mCheck = checksumRef.data;
    }

    public byte[] getBytes() {
        return mData;
    }

    public ECPublicKey getECPublicKey() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(EosPrivateKey.parameterSpec);
        ECPoint point = ecSpec.getCurve().decodePoint(getBytes());
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        return (ECPublicKey) keyFactory.generatePublic(pubSpec);
    }

    @Override
    public String toString() {

        boolean isR1 = mCurveParam.isType( CurveParam.SECP256_R1 );

        return EosEcUtil.encodeEosCrypto( isR1 ? PREFIX : LEGACY_PREFIX, isR1 ? mCurveParam : null, mData );

    }

    @Override
    public int hashCode(){
        return (int)(mCheck & 0xFFFFFFFFL );
    }

    @Override
    public boolean equals(Object other) {
        if ( this == other ){
            return true;
        }

        if ( null == other || getClass() != other.getClass())
        {
            return false;
        }

        if ( this.isCurveParamK1() != ((EosPublicKey)other).isCurveParamK1()) {
            return false;
        }

        return BitUtils.areEqual( this.mData, ((EosPublicKey)other).mData);
    }

    public boolean isCurveParamK1() {
        return ( mCurveParam == null || CurveParam.SECP256_K1 == mCurveParam.getCurveParamType() );
    }
}
