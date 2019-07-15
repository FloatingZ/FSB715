package com.h3xstream.findsecbugs.TransferParamFieldReturn;

public class FieldsToParam extends BaseTranser{
    private String methodName;
    private int fromIndex;
    private int[] toIndex;

    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public int getFromIndex() {
        return fromIndex;
    }

    public void setFromIndex(int fromIndex) {
        this.fromIndex = fromIndex;
    }

    public int[] getToIndex() {
        return toIndex;
    }

    public void setToIndex(int[] toIndex) {
        this.toIndex = toIndex;
    }
}
