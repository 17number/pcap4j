/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class UnknownPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4601589840627505036L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return a new UnknownPacket object.
   */
  public static UnknownPacket newPacket(byte[] rawData) {
    return new UnknownPacket(rawData);
  }

  private UnknownPacket(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    this.rawData = new byte[rawData.length];
    System.arraycopy(rawData, 0, this.rawData, 0, rawData.length);
  }

  private UnknownPacket(Builder builder) {
    if (
         builder == null
      || builder.rawData == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.rawData: ").append(builder.rawData);
      throw new NullPointerException(sb.toString());
    }

    // データパケットを同じバッファで使いまわせるよう修正
    // (データサイズに合わせて、new し直さなくて良いように)
    int length;
    if(builder.payloadLen == -1) {
      length = builder.rawData.length;
    }
    else {
      length = builder.payloadLen;
    }
    this.rawData = new byte[length];
    System.arraycopy(
      builder.rawData, 0, this.rawData, 0, length
    );
  }

  @Override
  public int length() { return rawData.length; }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends AbstractBuilder {

    private byte[] rawData;
    private int payloadLen;

    /**
     *
     */
    public Builder() {
      payloadLen = -1;
    }

    private Builder(UnknownPacket packet) {
      rawData = packet.rawData;
      payloadLen = rawData.length;
    }

    /**
     *
     * @param rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    /**
     *
     * @param payloadLen
     * @return this Builder object for method chaining.
     */
    public Builder payloadLen(int payloadLen) {
      this.payloadLen = payloadLen;
      return this;
    }

    @Override
    public UnknownPacket build() {
      return new UnknownPacket(this);
    }

  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append("[data (")
      .append(length())
      .append(" bytes)]")
      .append(ls);
    sb.append("  Hex stream: ")
      .append(ByteArrays.toHexString(rawData, " "))
      .append(ls);

    return sb.toString();
  }

}
