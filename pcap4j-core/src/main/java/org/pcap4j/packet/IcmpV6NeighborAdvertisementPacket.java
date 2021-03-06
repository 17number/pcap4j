/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6NeighborAdvertisementPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 2928161747361401145L;

  private final IcmpV6NeighborAdvertisementHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV6NeighborAdvertisementPacket object.
   */
  public static IcmpV6NeighborAdvertisementPacket newPacket(byte[] rawData) {
    return new IcmpV6NeighborAdvertisementPacket(rawData);
  }

  private IcmpV6NeighborAdvertisementPacket(byte[] rawData) {
    this.header = new IcmpV6NeighborAdvertisementHeader(rawData);
  }

  private IcmpV6NeighborAdvertisementPacket(Builder builder) {
    if (
         builder == null
      || builder.targetAddress == null
      || builder.options == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.targetAddress: ").append(builder.targetAddress)
        .append(" builder.options: ").append(builder.options);
      throw new NullPointerException(sb.toString());
    }

    this.header = new IcmpV6NeighborAdvertisementHeader(builder);
  }

  @Override
  public IcmpV6NeighborAdvertisementHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder extends AbstractBuilder {

    private boolean routerFlag;
    private boolean solicitedFlag;
    private boolean overrideFlag;
    private int reserved;
    private Inet6Address targetAddress;
    private List<IpV6NeighborDiscoveryOption> options;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV6NeighborAdvertisementPacket packet) {
      this.routerFlag = packet.header.routerFlag; // R field
      this.solicitedFlag = packet.header.solicitedFlag; // S field
      this.overrideFlag = packet.header.overrideFlag; // O field
      this.reserved = packet.header.reserved;
      this.targetAddress = packet.header.targetAddress;
      this.options = packet.header.options;
    }

    /**
     *
     * @param routerFlag
     * @return this Builder object for method chaining.
     */
    public Builder routerFlag(boolean routerFlag) {
      this.routerFlag = routerFlag;
      return this;
    }

    /**
     *
     * @param solicitedFlag
     * @return this Builder object for method chaining.
     */
    public Builder solicitedFlag(boolean solicitedFlag) {
      this.solicitedFlag = solicitedFlag;
      return this;
    }

    /**
     *
     * @param overrideFlag
     * @return this Builder object for method chaining.
     */
    public Builder overrideFlag(boolean overrideFlag) {
      this.overrideFlag = overrideFlag;
      return this;
    }

    /**
     *
     * @param reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(int reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     *
     * @param targetAddress
     * @return this Builder object for method chaining.
     */
    public Builder targetAddress(Inet6Address targetAddress) {
      this.targetAddress = targetAddress;
      return this;
    }

    /**
     *
     * @param options
     * @return this Builder object for method chaining.
     */
    public Builder options(List<IpV6NeighborDiscoveryOption> options) {
      this.options = options;
      return this;
    }

    @Override
    public IcmpV6NeighborAdvertisementPacket build() {
      return new IcmpV6NeighborAdvertisementPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static
  final class IcmpV6NeighborAdvertisementHeader extends AbstractHeader {

    /*
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |R|S|O|                     Reserved                            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +                       Target Address                          +
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Options ...
     * +-+-+-+-+-+-+-+-+-+-+-+-
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 2755611686067943647L;

    private static final int R_S_O_RESERVED_OFFSET
      = 0;
    private static final int R_S_O_RESERVED_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int TARGET_ADDRESS_OFFSET
      = R_S_O_RESERVED_OFFSET + R_S_O_RESERVED_SIZE;
    private static final int TARGET_ADDRESS_SIZE
      = INET6_ADDRESS_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET
      = TARGET_ADDRESS_OFFSET + TARGET_ADDRESS_SIZE;

    private final boolean routerFlag; // R field
    private final boolean solicitedFlag; // S field
    private final boolean overrideFlag; // O field
    private final int reserved;
    private final Inet6Address targetAddress;
    private final List<IpV6NeighborDiscoveryOption> options;

    private IcmpV6NeighborAdvertisementHeader(byte[] rawData) {
      if (rawData.length < OPTIONS_OFFSET) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The raw data must be more than ")
          .append(OPTIONS_OFFSET - 1).append("bytes")
          .append(" to build this header. raw data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      int tmp = ByteArrays.getInt(rawData, R_S_O_RESERVED_OFFSET);
      this.routerFlag = (tmp & 0x80000000) != 0;
      this.solicitedFlag = (tmp & 0x40000000) != 0;
      this.overrideFlag = (tmp & 0x20000000) != 0;
      this.reserved = 0x1FFFFFFF & tmp;
      this.targetAddress = ByteArrays.getInet6Address(rawData, TARGET_ADDRESS_OFFSET);
      this.options = new ArrayList<IpV6NeighborDiscoveryOption>();
      int currentOffset = OPTIONS_OFFSET;
      while (currentOffset < rawData.length) {
        byte[] optRawData = ByteArrays.getSubArray(
                              rawData,
                              currentOffset,
                              rawData.length - currentOffset
                            );
        IpV6NeighborDiscoveryOptionType type
          = IpV6NeighborDiscoveryOptionType.getInstance(optRawData[0]);
        IpV6NeighborDiscoveryOption newOne
          = PacketFactories
              .getFactory(
                 IpV6NeighborDiscoveryOption.class,
                 IpV6NeighborDiscoveryOptionType.class
               ).newInstance(optRawData, type);
        options.add(newOne);
        currentOffset += newOne.length();
      }
    }

    private IcmpV6NeighborAdvertisementHeader(Builder builder) {
      if ((builder.reserved & 0xE0000000) != 0) {
        throw new IllegalArgumentException(
                "Invalid reserved: " + builder.reserved
              );
      }

      this.routerFlag = builder.routerFlag;
      this.solicitedFlag = builder.solicitedFlag;
      this.overrideFlag = builder.overrideFlag;
      this.reserved = builder.reserved;
      this.targetAddress = builder.targetAddress;
      this.options = new ArrayList<IpV6NeighborDiscoveryOption>(builder.options);
    }

    /**
     *
     * @return routerFlag
     */
    public boolean getRouterFlag() {
      return routerFlag;
    }

    /**
     *
     * @return solicitedFlag
     */
    public boolean getSolicitedFlag() {
      return solicitedFlag;
    }

    /**
     *
     * @return overrideFlag
     */
    public boolean getOverrideFlag() {
      return overrideFlag;
    }

    /**
     *
     * @return reserved
     */
    public int getReserved() {
      return reserved;
    }

    /**
     *
     * @return targetAddress
     */
    public Inet6Address getTargetAddress() {
      return targetAddress;
    }

    /**
     *
     * @return options
     */
    public List<IpV6NeighborDiscoveryOption> getOptions() {
      return new ArrayList<IpV6NeighborDiscoveryOption>(options);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      int tmp = 0x1FFFFFFF & reserved;
      if (routerFlag) {
        tmp |= 0x80000000;
      }
      if (solicitedFlag) {
        tmp |= 0x40000000;
      }
      if (overrideFlag) {
        tmp |= 0x20000000;
      }
      rawFields.add(ByteArrays.toByteArray(tmp));
      rawFields.add(ByteArrays.toByteArray(targetAddress));
      for (IpV6NeighborDiscoveryOption o: options) {
        rawFields.add(o.getRawData());
      }
      return rawFields;
    }

    @Override
    protected int measureLength() {
      int len = 0;
      for (IpV6NeighborDiscoveryOption o: options) {
        len += o.length();
      }
      return len + OPTIONS_OFFSET;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv6 Neighbor Advertisement Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Router flag: ")
        .append(routerFlag)
        .append(ls);
      sb.append("  Solicited flag: ")
        .append(solicitedFlag)
        .append(ls);
      sb.append("  Override flag: ")
        .append(overrideFlag)
        .append(ls);
      sb.append("  Reserved: ")
        .append(reserved)
        .append(ls);
      sb.append("  Target Address: ")
        .append(targetAddress)
        .append(ls);
      for (IpV6NeighborDiscoveryOption opt: options) {
        sb.append("  Option: ")
          .append(opt)
          .append(ls);
      }

      return sb.toString();
    }

  }

}
