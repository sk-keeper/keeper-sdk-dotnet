using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk
{
    public class EnterpriseData: IEnterprise
    {
        private readonly IAuthentication _auth;

        public byte[] TreeKey { get; private set; }

        public EnterpriseData(IAuthentication auth)
        {
            _auth = auth;
        }

        internal readonly Dictionary<string, byte[]> UserPublicKeyCache = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);

        private readonly ConcurrentDictionary<long, EnterpriseNode> _nodes = new ConcurrentDictionary<long, EnterpriseNode>();
        private readonly ConcurrentDictionary<long, EnterpriseUser> _users = new ConcurrentDictionary<long, EnterpriseUser>();
        private readonly ConcurrentDictionary<string, EnterpriseTeam> _teams = new ConcurrentDictionary<string, EnterpriseTeam>();
        private readonly ConcurrentDictionary<string, long> _userNames = new ConcurrentDictionary<string, long>(1, 100, StringComparer.InvariantCultureIgnoreCase);
        public async Task GetEnterpriseData()
        {
            var rq = new GetEnterpriseDataCommand
            {
                include = new [] {"nodes", "users", "teams", "team_users" }
            };
            var rs = await _auth.ExecuteAuthCommand<GetEnterpriseDataCommand, GetEnterpriseDataResponse>(rq);

            var encTreeKey = rs.TreeKey.Base64UrlDecode();
            switch (rs.KeyTypeId)
            {
                case 1:
                    TreeKey = CryptoUtils.DecryptAesV1(encTreeKey, _auth.AuthContext.DataKey);
                    break;
                case 2:
                    TreeKey = CryptoUtils.DecryptRsa(encTreeKey, _auth.AuthContext.PrivateKey);
                    break;
                default:
                    throw new Exception("cannot decrypt tree key");
            }

            var ids = new HashSet<long>(_nodes.Keys);
            foreach (var n in rs.Nodes)
            {
                if (_nodes.TryGetValue(n.NodeId, out var node))
                {
                    ids.Remove(n.NodeId);
                    node.Subnodes.Clear();
                }
                else
                {
                    node = new EnterpriseNode {Id = n.NodeId};
                    _nodes.TryAdd(n.NodeId, node);
                }

                if (n.ParentId.HasValue && n.ParentId.Value > 0)
                {
                    node.ParentNodeId = n.ParentId.Value;
                }
                else
                {
                    RootNode = node;
                    node.ParentNodeId = 0;
                }

                EnterpriseUtils.DecryptEncryptedData(n, TreeKey, node);
            }
            foreach (var id in ids)
            {
                _nodes.TryRemove(id, out _);
            }

            foreach (var node in _nodes.Values)
            {
                if (node.ParentNodeId <= 0) continue;
                if (_nodes.TryGetValue(node.ParentNodeId, out var parent))
                {
                    parent.Subnodes.Add(node.Id);
                }
            }

            if (rs.Users != null)
            {
                ids.Clear();
                ids.UnionWith(_users.Keys);
                foreach (var u in rs.Users)
                {
                    if (_users.TryGetValue(u.EnterpriseUserId, out var user))
                    {
                        ids.Remove(u.EnterpriseUserId);
                        user.Teams.Clear();
                    }
                    else
                    {
                        user = new EnterpriseUser
                        {
                            Id = u.EnterpriseUserId
                        };
                        _users.TryAdd(u.EnterpriseUserId, user);
                    }

                    user.ParentNodeId = u.NodeId;
                    user.Email = u.Username;
                    EnterpriseUtils.DecryptEncryptedData(u, TreeKey, user);

                    if (u.Status == "active")
                    {
                        switch (u.Lock)
                        {
                            case 0:
                                user.UserStatus = UserStatus.Active;
                                break;
                            case 1:
                                user.UserStatus = UserStatus.Locked;
                                break;
                            case 2:
                                user.UserStatus = UserStatus.Disabled;
                                break;
                            default:
                                user.UserStatus = UserStatus.Active;
                                break;
                        }
                        if (u.AccountShareExpiration.HasValue && u.AccountShareExpiration.Value > 0)
                        {
                            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                            if (now > (long) u.AccountShareExpiration.Value)
                            {
                                user.UserStatus = UserStatus.Blocked;
                            }
                        }
                    }
                    else
                    {
                        user.UserStatus = UserStatus.Inactive;
                    }
                }

                foreach (var id in ids)
                {
                    _users.TryRemove(id, out _);
                }
                _userNames.Clear();
                foreach (var u in rs.Users)
                {
                    _userNames.TryAdd(u.Username, u.EnterpriseUserId);
                }
            }

            if (rs.Teams != null)
            {
                var uids = new HashSet<string>();
                uids.UnionWith(_teams.Keys);
                foreach (var t in rs.Teams)
                {
                    if (_teams.TryGetValue(t.TeamUid, out var team))
                    {
                        uids.Remove(t.TeamUid);
                        team.Users.Clear();
                    }
                    else
                    {
                        team = new EnterpriseTeam
                        {
                            Uid = t.TeamUid
                        };
                        _teams.TryAdd(t.TeamUid, team);
                    }

                    team.Name = t.Name;

                    team.ParentNodeId = t.NodeId;
                    team.RestrictEdit = t.RestrictEdit;
                    team.RestrictSharing = t.RestrictSharing;
                    team.RestrictView = t.RestrictView;
                    if (!string.IsNullOrEmpty(t.EncryptedTeamKey))
                    {
                        try
                        {
                            team.TeamKey = CryptoUtils.DecryptAesV2(t.EncryptedTeamKey.Base64UrlDecode(), TreeKey);
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.Message);
                        }
                    }
                }

                foreach (var uid in uids)
                {
                    _teams.TryRemove(uid, out _);
                }
            }

            if (rs.TeamUsers != null)
            {
                foreach (var tu in rs.TeamUsers)
                {
                    if (_users.TryGetValue(tu.EnterpriseUserId, out var user) && _teams.TryGetValue(tu.TeamUid, out var team))
                    {
                        team.Users.Add(user.Id);
                        user.Teams.Add(team.Uid);
                    }
                }
            }
        }

        public IAuthentication Auth => _auth;
        public IEnumerable<EnterpriseNode> Nodes => _nodes.Values;
        public bool TryGetNode(long nodeId, out EnterpriseNode node)
        {
            return _nodes.TryGetValue(nodeId, out node);
        }
        public int NodeCount => _nodes.Count;
        public EnterpriseNode RootNode { get; private set; }

        public IEnumerable<EnterpriseUser> Users => _users.Values;
        public bool TryGetUserById(long userId, out EnterpriseUser user)
        {
            return _users.TryGetValue(userId, out user);
        }

        public bool TryGetUserByEmail(string email, out EnterpriseUser user)
        {
            if (!_userNames.TryGetValue(email, out var id))
            {
                user = null;
                return false;
            }

            return _users.TryGetValue(id, out user);
        }

        public int UserCount => _users.Count;

        public IEnumerable<EnterpriseTeam> Teams => _teams.Values;

        public bool TryGetTeam(string teamUid, out EnterpriseTeam team)
        {
            return _teams.TryGetValue(teamUid, out team);
        }

        public int TeamCount => _teams.Count;

        public async Task AddUsersToTeams(string[] emails, string[] teamUids, Action<string> warnings = null)
        {
            var userPublicKeys = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var email in emails)
            {
                if (!TryGetUserByEmail(email, out var user))
                {
                    var message = $"User {email} not found.";
                    if (warnings != null)
                    {
                        warnings.Invoke(message);
                    }
                    else
                    {
                        throw new EnterpriseException(message);
                    }
                }
                else
                {
                    if (user.UserStatus != UserStatus.Active)
                    {
                        var message = $"User \'{user.Email}\' cannot be added to a team: user is not active.";
                        if (warnings != null)
                        {
                            warnings.Invoke(message);
                        }
                        else
                        {
                            throw new EnterpriseException(message);
                        }
                    }
                    else
                    {
                        userPublicKeys[user.Email] = null;
                    }
                }
            }

            if (userPublicKeys.Count == 0)
            {
                warnings?.Invoke($"No users to add");
                return;
            }

            var teamKeys = new Dictionary<string, byte[]>();
            foreach (var teamUid in teamUids)
            {
                if (TryGetTeam(teamUid, out var team))
                {
                    teamKeys[teamUid] = null;
                }
                else
                {
                    var message = $"Team UID {teamUid} not found.";
                    if (warnings != null)
                    {
                        warnings.Invoke(message);
                    }
                    else
                    {
                        throw new EnterpriseException(message);
                    }
                }
            }
            if (teamKeys.Count == 0)
            {
                warnings?.Invoke($"No teams to add");
                return;
            }

            await this.PopulateUserPublicKeys(userPublicKeys, warnings);
            await this.PopulateTeamKeys(teamKeys, warnings);

            var commands = new List<KeeperApiCommand>();
            foreach (var userPair in userPublicKeys.Where(x => x.Value != null))
            {
                if (userPair.Value == null) continue;
                if (!TryGetUserByEmail(userPair.Key, out var user)) continue;
                try
                {
                    var publicKey = CryptoUtils.LoadPublicKey(userPair.Value);
                    foreach (var teamPair in teamKeys.Where(x => x.Value != null))
                    {
                        if (!TryGetTeam(teamPair.Key, out var team)) continue;
                        if (team.Users.Contains(user.Id)) continue;
                        var teamKey = teamPair.Value;
                        commands.Add(new TeamEnterpriseUserAddCommand
                        {
                            TeamUid = team.Uid,
                            EnterpriseUserId = user.Id,
                            TeamKey = CryptoUtils.EncryptRsa(teamKey, publicKey).Base64UrlEncode(),
                            UserType = 0,
                        });
                    }
                }
                catch (Exception e)
                {
                    warnings?.Invoke(e.Message);
                    Debug.WriteLine(e);
                }
            }

            if (commands.Count > 0)
            {
                var batch = commands.Take(99).ToList();
                var execRq = new ExecuteCommand
                {
                    Requests = batch
                };
                var execRs = await Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(execRq);
                if (execRs.Results?.Count > 0)
                {
                    var last = execRs.Results.Last();
                    var success = execRs.Results.Count + (last.IsSuccess ? 0 : -1);
                    warnings?.Invoke($"Successfully added {success} team membership(s)");
                    if (!last.IsSuccess)
                    {
                        warnings?.Invoke(last.message);
                    }
                }
            }
        }

        public async Task RemoveUsersFromTeams(string[] emails, string[] teamUids, Action<string> warnings = null)
        {
            var commands = new List<KeeperApiCommand>();
            foreach (var teamUid in teamUids)
            {
                if (!TryGetTeam(teamUid, out var team))
                {
                    warnings?.Invoke($"Team UID \'{teamUid}\' not found");
                    continue;
                }

                foreach (var email in emails)
                {
                    if (TryGetUserByEmail(email, out var user))
                    {
                        if (!team.Users.Contains(user.Id))
                        {
                            user = null;
                        }
                    }

                    if (user == null)
                    {
                        warnings?.Invoke($"User \'{email}\' does not belong to team \'{team.Name}\'");
                        continue;
                    }

                    commands.Add(new TeamEnterpriseUserRemoveCommand
                    {
                        TeamUid = team.Uid,
                        EnterpriseUserId = user.Id,
                    });
                }
            }

            if (commands.Count > 0)
            {
                var batch = commands.Take(99).ToList();
                var execRq = new ExecuteCommand
                {
                    Requests = batch
                };
                var execRs = await Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(execRq);
                if (execRs.Results?.Count > 0)
                {
                    var last = execRs.Results.Last();
                    var success = execRs.Results.Count + (last.IsSuccess ? 0 : -1);
                    warnings?.Invoke($"Successfully removed {success} team membership(s)");
                    if (!last.IsSuccess)
                    {
                        warnings?.Invoke(last.message);
                    }
                }
            }
        }
    }
}
