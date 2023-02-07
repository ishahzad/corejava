package com.ishahzadtech.common;

/**
 * Thrown to signify operation failure during execution of a program.
 * 
 * @author ishahzad (Irfan Shahzad) - ishahzadtech.com
 * @since 1.0
 */
@SuppressWarnings("serial")
public class OperationFailureException extends RuntimeException {

	public OperationFailureException(String message) {
        super(message);
    }
	
	public OperationFailureException(String message, Throwable cause) {
        super(message, cause);
    }
}
