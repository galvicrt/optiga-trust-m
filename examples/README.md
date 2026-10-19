# Examples

This folders are used to demonstrate basic functionality of the security chip. 

The list of available Host Applications, Platform and current status can be found in the table below :

| Host application                                                                                                                                                       | Operating System | Status |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ------ |
| [OPTIGA™ Trust M Cryptography](https://github.com/Infineon/mtb-example-optiga-crypto)                                                                                  | Native           | Active |
| [OPTIGA™ Trust M MQTT Client](https://github.com/Infineon/mtb-example-optiga-mqtt-client)                                                                              | FreeRTOS         | Active |
| [OPTIGA™ Trust M Power management](https://github.com/Infineon/mtb-example-optiga-power-management)                                                                    | Native           | Active |
| [OPTIGA™ Trust M Data management](https://github.com/Infineon/mtb-example-optiga-data-management)                                                                      | Native           | Active |
| [OPTIGA™ Trust M TLS with mbedTLS](https://github.com/Infineon/mbedtls-optiga-trust-m)                                                                                 | Native           | Active |
| [OPTIGA™ Trust M AWS FreeRTOS](https://github.com/Infineon/amazon-freertos-optiga-trust)                                                                               | FreeRTOS         | Active |
| [OPTIGA™ Trust M Microsoft Azure IoT](https://github.com/Infineon/azure-esp32-optiga-trust/)                                                                           | FreeRTOS         | Active |
| [OPTIGA™ Trust M PKCS#11 interface](https://github.com/Infineon/pkcs11-optiga-trust-m)                                                                                 | Linux            | Active |
| [OPTIGA™ Trust M Matter integration](https://github.com/project-chip/connectedhomeip/tree/master/examples/lock-app/infineon/psoc6#building-with-optiga-trust-m-as-hsm) | Linux            | Active |
| [OPTIGA™ Trust M Zephyr PAL & Application](https://github.com/Infineon/optiga-trust-m-zephyr)                                                                          | Zephyr           | Active |

## Secure sensor record example: persistent provisioning changes

[`example_optiga_secure_sensor_record`](optiga/usecases/example_optiga_secure_sensor_record.c)
is intended only for disposable test devices. Its provisioning helper changes shared
object `0xF1D0` to **Execute = Always** and **type = Pre-shared secret**, then erases
and replaces its contents with a **public, hardcoded sample HMAC secret**. This can
break other examples or applications that use the same object.

These writes persist after completion, errors, and application close. In particular,
a successful metadata write remains even if the subsequent secret write fails.
The example does not save or restore the previous metadata or secret. A general
rollback cannot recover an overwritten secret when the object's read policy prevents
reading it. Before reusing the device, reprovision `0xF1D0` with the intended secret
and access policy using your device's provisioning procedure.

# Troubleshooting

## 0x107 (handshake error)

Some of the examples, for instance [`example_optiga_util_read_data`](https://github.com/Infineon/optiga-trust-m/blob/master/examples/optiga/example_optiga_util_read_data.c#L61) calls
```
// OPTIGA Comms Shielded connection settings to enable the protection
OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me, OPTIGA_COMMS_RESPONSE_PROTECTION);
```
Which afterwards raises the **0x107 handshake error**. In most of the cases it happens because the [Pairing](https://github.com/Infineon/optiga-trust-m/wiki/Shielded-Connection-101#pairing) didn't happen. In this case you need either to remove these two lines of the code, or [pair](https://github.com/Infineon/optiga-trust-m/blob/master/examples/optiga/usecases/example_pair_host_and_optiga_using_pre_shared_secret.c) your device with the secure element.
