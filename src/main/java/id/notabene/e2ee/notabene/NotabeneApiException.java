package id.notabene.e2ee.notabene;

public class NotabeneApiException extends RuntimeException {

    private final int status;
    private final String body;

    public NotabeneApiException(String message, int status, String body) {
        super(message);
        this.status = status;
        this.body = body;
    }

    public int getStatus() {
        return status;
    }

    public String getBody() {
        return body;
    }
}
