package org.asanka.test.jmeter.ext.exception;

public class JmeterJWTExtException extends Exception {
    public JmeterJWTExtException() {

    }

    public JmeterJWTExtException(String s) {
        super(s);
    }

    public JmeterJWTExtException(Throwable throwable) {
        super(throwable);
    }

    public JmeterJWTExtException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
