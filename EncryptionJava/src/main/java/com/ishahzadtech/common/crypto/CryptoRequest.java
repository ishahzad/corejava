package com.ishahzadtech.common.crypto;

import java.security.Key;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

@AllArgsConstructor
public class CryptoRequest {

	@Getter
	@NonNull
	private String algorithm;

	@Getter
	private Key cryptoKey;

	@Getter
	private byte[] iv;

	@Getter
	@NonNull
	private byte[] data;
}
