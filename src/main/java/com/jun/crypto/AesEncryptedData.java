package com.jun.crypto;

final class AesEncryptedData {
    private final byte[] encryptedData;
    private final byte[] iv;

    public AesEncryptedData(byte[] encryptedData, byte[] iv){
        this.encryptedData = encryptedData;
        this.iv = iv;
    }

    public byte[] getEncryptedData(){
        return encryptedData;
    }
    public byte[] getIv(){
        return iv;
    }
}
