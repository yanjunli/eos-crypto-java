package com.eos.crypto.util;

public class Arrays {

    public static byte[] copyOfRange(byte[] original, int from, int to) {
        int newLength = to - from;
        if (newLength < 0){
            throw new IllegalArgumentException(from + " > " + to);
        }
        byte[] copy = new byte[newLength];
        System.arraycopy(original, from, copy, 0,
                Math.min(original.length - from, newLength));
        return copy;
    }

    public static byte[] copyOf(byte[] original, int newLength) {
        byte[] copy = new byte[newLength];
        System.arraycopy(original, 0, copy, 0,
                Math.min(original.length, newLength));
        return copy;
    }

    public static boolean equals(byte[] a, byte[] a2) {
        if (a==a2){
            return true;
        }

        if (a==null || a2==null){
            return false;
        }


        int length = a.length;
        if (a2.length != length){
            return false;
        }

        for (int i=0; i<length; i++){
            if (a[i] != a2[i]){
                return false;
            }
        }
        return true;
    }
}
