/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalIpV6Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6Pad1Option;
import org.pcap4j.packet.IpV6PadNOption;
import org.pcap4j.packet.UnknownIpV6Option;
import org.pcap4j.packet.namednumber.IpV6OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6OptionFactory
implements PacketFactory<IpV6Option, IpV6OptionType> {

  private static final StaticIpV6OptionFactory INSTANCE
    = new StaticIpV6OptionFactory();
  private final Map<IpV6OptionType, Instantiater> instantiaters
    = new HashMap<IpV6OptionType, Instantiater>();

  private StaticIpV6OptionFactory() {
    instantiaters.put(
      IpV6OptionType.PAD1, new Instantiater() {
        @Override
        public IpV6Option newInstance(byte[] rawData) {
          return IpV6Pad1Option.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV6OptionType.PADN, new Instantiater() {
        @Override
        public IpV6Option newInstance(byte[] rawData) {
          return IpV6PadNOption.newInstance(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticIpV6OptionFactory.
   */
  public static StaticIpV6OptionFactory getInstance() {
    return INSTANCE;
  }

  public IpV6Option newInstance(
    byte[] rawData, IpV6OptionType number
  ) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData);
    }

    return UnknownIpV6Option.newInstance(rawData);
  }

  public IpV6Option newInstance(byte[] rawData) {
    return UnknownIpV6Option.newInstance(rawData);
  }

  private static abstract class Instantiater {

    public abstract IpV6Option newInstance(byte [] rawData);

  }

}
