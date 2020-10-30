using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Authentication;
using CommandLine;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Sdk;
using Org.BouncyCastle.Crypto.Parameters;
using KeyType = Enterprise.KeyType;

namespace Commander
{
    public partial class ConnectedContext
    {
        private EnterpriseData _enterprise = null;

        private Dictionary<long, byte[]> _userDataKeys = new Dictionary<long, byte[]>();
        private GetDeviceForAdminApproval[] _deviceForAdminApprovals;

        private bool _autoApproveAdminRequests = false;
        private ECPrivateKeyParameters _enterprisePrivateKey;

        private void CheckIfEnterpriseAdmin()
        {
            if (_auth.AuthContext.IsEnterpriseAdmin)
            {
                _enterprise = new EnterpriseData(_auth);

                lock (Commands)
                {
                    _auth.AuthContext.PushNotifications.RegisterCallback(EnterpriseNotificationCallback);

                    Commands.Add("enterprise-node",
                        new ParsableCommand<EnterpriseNodeOptions>
                        {
                            Order = 60,
                            Description = "Display node structure ",
                            Action = EnterpriseNodeCommand,
                        });

                    Commands.Add("enterprise-user",
                        new ParsableCommand<EnterpriseUserOptions>
                        {
                            Order = 61,
                            Description = "List Enterprise Users",
                            Action = EnterpriseUserCommand,
                        });

                    Commands.Add("enterprise-device",
                        new ParsableCommand<EnterpriseDeviceOptions>
                        {
                            Order = 62,
                            Description = "Manage User Devices",
                            Action = EnterpriseDeviceCommand,
                        });

                    CommandAliases["en"] = "enterprise-node";
                    CommandAliases["eu"] = "enterprise-user";
                    CommandAliases["ed"] = "enterprise-device";
                }

                Task.Run(async () =>
                {
                    try
                    {
                        await _enterprise.GetEnterpriseData();

                        var keysRq = new GetEnterpriseDataCommand
                        {
                            include = new[] {"keys"}
                        };
                        var keysRs = await _auth.ExecuteAuthCommand<GetEnterpriseDataCommand, GetEnterpriseDataResponse>(keysRq);
                        if (string.IsNullOrEmpty(keysRs.Keys?.EccEncryptedPrivateKey))
                        {
                            Commands.Add("enterprise-add-key",
                                new SimpleCommand
                                {
                                    Order = 63,
                                    Description = "Register ECC key pair",
                                    Action = EnterpriseRegisterEcKey,
                                });
                        }
                        else
                        {
                            var privateKeyData = CryptoUtils.DecryptAesV2(keysRs.Keys.EccEncryptedPrivateKey.Base64UrlDecode(), _enterprise.TreeKey);
                            _enterprisePrivateKey = CryptoUtils.LoadPrivateEcKey(privateKeyData);
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }
                });
            }
        }

        class EnterpriseGenericOptions
        {
            [Option('f', "force", Required = false, Default = false, HelpText = "force reload enterprise data")]
            public bool Force { get; set; }
        }

        class EnterpriseNodeOptions : EnterpriseGenericOptions
        {
            [Value(0, Required = false, HelpText = "enterprise-node command: \"tree\"")]
            public string Command { get; set; }
        }

        class EnterpriseUserOptions : EnterpriseGenericOptions
        {
            [Value(0, Required = false, HelpText = "enterprise-node command: \"list\"")]
            public string Command { get; set; }

            [Option("match", Required = false, HelpText = "Filter matching user information")]
            public string Match { get; set; }
        }

        class EnterpriseDeviceOptions : EnterpriseGenericOptions
        {
            [Option("auto-approve", Required = false, Default = null, HelpText = "auto approve devices")]
            public bool? AutoApprove { get; set; }

            [Value(0, Required = false, HelpText = "enterprise-device command: \"list\", \"approve\", \"decline\"")]
            public string Command { get; set; }

            [Value(1, Required = false, HelpText = "enterprise-device command: \"list\", \"approve\", \"decline\"")]
            public string Match { get; set; }
        }
        
        public async Task GetEnterpriseData(params string[] includes)
        {
            var requested = new HashSet<string>(includes);
            var rq = new GetEnterpriseDataCommand
            {
                include = requested.ToArray()
            };
            var rs = await _auth.ExecuteAuthCommand<GetEnterpriseDataCommand, GetEnterpriseDataResponse>(rq);
            if (requested.Contains("devices_request_for_admin_approval"))
            {
                _deviceForAdminApprovals = rs.DeviceRequestForApproval != null ? rs.DeviceRequestForApproval.ToArray() : new GetDeviceForAdminApproval[0];
            }
        }

        public void PrintNodeTree(EnterpriseNode eNode, string indent, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + eNode.DisplayName);
            indent += isRoot ? " " : (last ? "    " : "|   ");
            var subNodes = eNode.Subnodes
                .Select(x => _enterprise.TryGetNode(x, out var node) ? node : null)
                .Where(x => x != null)
                .OrderBy(x => x.DisplayName ?? "")
                .ToArray();
            for (var i = 0; i < subNodes.Length; i++)
            {
                PrintNodeTree(subNodes[i], indent, i == subNodes.Length - 1);
            }
        }

        private async Task EnterpriseNodeCommand(EnterpriseNodeOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "tree";

            if (arguments.Force)
            {
                await _enterprise.GetEnterpriseData();
            }

            if (_enterprise.RootNode == null) throw new Exception("Enterprise data: cannot get root node");
            switch (arguments.Command.ToLowerInvariant())
            {
                case "tree":
                {
                    PrintNodeTree(_enterprise.RootNode, "", true);
                }
                    break;
                default:
                    Console.WriteLine($"Unsupported command \"{arguments.Command}\": available commands \"tree\"");
                    break;
            }
        }

        private async Task EnterpriseUserCommand(EnterpriseUserOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";

            if (arguments.Force)
            {
                await _enterprise.GetEnterpriseData();
            }

            switch (arguments.Command.ToLowerInvariant())
            {
                case "list":
                {
                    var users = _enterprise.Users
                        .Where(x =>
                        {
                            if (string.IsNullOrEmpty(arguments.Match)) return true;
                            var m = Regex.Match(x.Email, arguments.Match, RegexOptions.IgnoreCase);
                            if (m.Success) return true;
                            if (!string.IsNullOrEmpty(x.DisplayName))
                            {
                                m = Regex.Match(x.DisplayName, arguments.Match, RegexOptions.IgnoreCase);
                                if (m.Success) return true;
                            }

                            var status = x.UserStatus.ToString();
                            m = Regex.Match(status, arguments.Match, RegexOptions.IgnoreCase);
                            return m.Success;
                        })
                        .ToArray();

                    var tab = new Tabulate(3)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader(new[] {"Email", "Display Name", "Status"});
                    foreach (var user in users)
                    {
                        tab.AddRow(new[] {user.Email, user.DisplayName, user.UserStatus.ToString()});
                    }

                    tab.Sort(1);
                    tab.Dump();
                }
                    break;
                default:
                    Console.WriteLine($"Unsupported command \"{arguments.Command}\": available commands \"list\"");
                    break;
            }
        }

        private bool EnterpriseNotificationCallback(NotificationEvent evt)
        {
            if (evt.Event == "request_device_admin_approval")
            {
                if (_autoApproveAdminRequests)
                {
                    Task.Run(async () =>
                    {
                        await GetEnterpriseData("devices_request_for_admin_approval");
                        if (!_enterprise.TryGetUserByEmail(evt.Email, out var user))
                        {
                            await _enterprise.GetEnterpriseData();
                            if (!_enterprise.TryGetUserByEmail(evt.Email, out user)) return;
                        }

                        var devices = _deviceForAdminApprovals
                            .Where(x => x.EnterpriseUserId == user.Id)
                            .ToArray();
                        await ApproveAdminDeviceRequests(devices);
                        Console.WriteLine($"Auto approved {evt.Email} at IP Address {evt.IPAddress}.");
                    });
                }
                else
                {
                    Console.WriteLine($"\n{evt.Email} requested Device Approval\nIP Address: {evt.IPAddress}\nDevice Name: {evt.DeviceName}");
                    _deviceForAdminApprovals = null;
                }
            }

            return false;
        }

        private async Task DenyAdminDeviceRequests(GetDeviceForAdminApproval[] devices)
        {
            var rq = new ApproveUserDevicesRequest();
            foreach (var device in devices)
            {
                var deviceRq = new ApproveUserDeviceRequest
                {
                    EnterpriseUserId = device.EnterpriseUserId,
                    EncryptedDeviceToken = ByteString.CopyFrom(device.EncryptedDeviceToken.Base64UrlDecode()),
                    DenyApproval = true,
                };
                rq.DeviceRequests.Add(deviceRq);
                if (rq.DeviceRequests.Count == 0)
                {
                    Console.WriteLine($"No device to approve/deny");
                }
                else
                {
                    var rs = await _auth
                        .ExecuteAuthRest<ApproveUserDevicesRequest, ApproveUserDevicesResponse>("enterprise/approve_user_devices", rq);
                    if (rs.DeviceResponses?.Count > 0)
                    {
                        foreach (var approveRs in rs.DeviceResponses)
                        {
                            if (!approveRs.Failed) continue;
                            if (_enterprise.TryGetUserById(approveRs.EnterpriseUserId, out var user))
                            {
                                Console.WriteLine($"Failed to approve {user.Email}: {approveRs.Message}");
                            }
                        }
                    }

                    _deviceForAdminApprovals = null;
                }
            }
        }

        private async Task ApproveAdminDeviceRequests(GetDeviceForAdminApproval[] devices)
        {
            var dataKeys = new Dictionary<long, byte[]>();
            foreach (var device in devices)
            {
                if (!dataKeys.ContainsKey(device.EnterpriseUserId))
                {
                    dataKeys[device.EnterpriseUserId] = _userDataKeys.TryGetValue(device.EnterpriseUserId, out var dk) ? dk : null;
                }
            }

            var toLoad = dataKeys.Where(x => x.Value == null).Select(x => x.Key).ToArray();
            if (toLoad.Any() && _enterprisePrivateKey != null)
            {
                var dataKeyRq = new UserDataKeyRequest();
                dataKeyRq.EnterpriseUserId.AddRange(toLoad);
                var dataKeyRs = await _auth.ExecuteAuthRest<UserDataKeyRequest, EnterpriseUserDataKeys>("enterprise/get_enterprise_user_data_key", dataKeyRq);
                foreach (var key in dataKeyRs.Keys)
                {
                    if (key.UserEncryptedDataKey.IsEmpty) continue;
                    try
                    {
                        var userDataKey = CryptoUtils.DecryptEc(key.UserEncryptedDataKey.ToByteArray(), _enterprisePrivateKey);
                        _userDataKeys[key.EnterpriseUserId] = userDataKey;
                        dataKeys[key.EnterpriseUserId] = userDataKey;
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine($"Data key decrypt error: {e.Message}");
                    }
                }
            }

            var rq = new ApproveUserDevicesRequest();
            foreach (var device in devices)
            {
                if (!dataKeys.TryGetValue(device.EnterpriseUserId, out var dk)) continue;
                if (string.IsNullOrEmpty(device.DevicePublicKey)) continue;
                var devicePublicKey = CryptoUtils.LoadPublicEcKey(device.DevicePublicKey.Base64UrlDecode());

                try
                {
                    var deviceRq = new ApproveUserDeviceRequest
                    {
                        EnterpriseUserId = device.EnterpriseUserId,
                        EncryptedDeviceToken = ByteString.CopyFrom(device.EncryptedDeviceToken.Base64UrlDecode()),
                        EncryptedDeviceDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(dk, devicePublicKey))
                    };
                    rq.DeviceRequests.Add(deviceRq);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            }
            if (rq.DeviceRequests.Count == 0)
            {
                Console.WriteLine($"No device to approve/deny");
            }
            else
            {
                var rs = await 
                    _auth.ExecuteAuthRest<ApproveUserDevicesRequest, ApproveUserDevicesResponse>("enterprise/approve_user_devices", rq);
                if (rs.DeviceResponses?.Count > 0)
                {
                    foreach (var approveRs in rs.DeviceResponses)
                    {
                        if (!approveRs.Failed) continue;

                        if (_enterprise.TryGetUserById(approveRs.EnterpriseUserId, out var user))
                        {
                            Console.WriteLine($"Failed to approve {user.Email}: {approveRs.Message}");
                        }
                    }
                }
                _deviceForAdminApprovals = null;
            }
        }

        private async Task EnterpriseDeviceCommand(EnterpriseDeviceOptions arguments)
        {
            if (arguments.AutoApprove.HasValue)
            {
                _autoApproveAdminRequests = arguments.AutoApprove.Value;
                Console.WriteLine($"Automatic Admin Device Approval is {(_autoApproveAdminRequests ? "ON" : "OFF")}");
            }

            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";

            if (arguments.Force || _deviceForAdminApprovals == null)
            {
                await GetEnterpriseData("devices_request_for_admin_approval");
            }

            if (_deviceForAdminApprovals.Length == 0)
            {
                Console.WriteLine("There are no pending devices");
                return;
            }

            var cmd = arguments.Command.ToLowerInvariant();
            switch (cmd)
            {
                case "list":
                    var tab = new Tabulate(4)
                    {
                        DumpRowNo = false
                    };
                    Console.WriteLine();
                    tab.AddHeader(new[] {"Email", "Device ID", "Device Name", "Client Version"});
                    foreach (var device in _deviceForAdminApprovals)
                    {
                        if (!_enterprise.TryGetUserById(device.EnterpriseUserId, out var user)) continue;
                        
                        tab.AddRow(new[] {user.Email, TokenToString(device.EncryptedDeviceToken.Base64UrlDecode()), device.DeviceName, device.ClientVersion});
                    }

                    tab.Sort(1);
                    tab.Dump();
                    break;

                case "approve":
                case "deny":
                    if (string.IsNullOrEmpty(arguments.Match))
                    {
                        Console.WriteLine($"{arguments.Command} command requires device ID or user email parameter.");
                    }
                    else
                    {
                        var devices = _deviceForAdminApprovals
                            .Where(x =>
                            {
                                if (arguments.Match == "all") return true;
                                var deviceId = TokenToString(x.EncryptedDeviceToken.Base64UrlDecode());
                                if (deviceId.StartsWith(arguments.Match)) return true;

                                if (!_enterprise.TryGetUserById(x.EnterpriseUserId, out var user)) return false;
                                return user.Email == arguments.Match;

                            }).ToArray();

                        if (devices.Length > 0)
                        {
                            if (cmd == "approve")
                            {
                                await ApproveAdminDeviceRequests(devices);
                            }
                            else
                            {
                                await DenyAdminDeviceRequests(devices);
                            }
                        }
                        else
                        {
                            Console.WriteLine($"No device found matching {arguments.Match}");
                        }
                    }

                    break;
            }
        }

        private async Task EnterpriseRegisterEcKey(string _)
        {
            if (_enterprise.TreeKey == null)
            {
                Console.WriteLine("Cannot get tree key");
                return;
            }

            CryptoUtils.GenerateEcKey(out var privateKey, out var publicKey);
            var exportedPublicKey = CryptoUtils.UnloadEcPublicKey(publicKey);
            var exportedPrivateKey = CryptoUtils.UnloadEcPrivateKey(privateKey);
            var encryptedPrivateKey = CryptoUtils.EncryptAesV2(exportedPrivateKey, _enterprise.TreeKey);
            var request = new EnterpriseKeyPairRequest
            {
                KeyType = KeyType.Ecc,
                EnterprisePublicKey = ByteString.CopyFrom(exportedPublicKey),
                EncryptedEnterprisePrivateKey = ByteString.CopyFrom(encryptedPrivateKey),
            };

            await _auth.ExecuteAuthRest("enterprise/set_enterprise_key_pair", request);
            Commands.Remove("enterprise-add-key");
        }
    }
}
