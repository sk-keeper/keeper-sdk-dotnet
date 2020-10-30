using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk
{
    public interface IEnterprise
    {
        IEnumerable<EnterpriseNode> Nodes { get; }
        bool TryGetNode(long nodeId, out EnterpriseNode node);
        int NodeCount { get; }
        EnterpriseNode RootNode { get; }

        IEnumerable<EnterpriseUser> Users { get; }
        bool TryGetUserById(long userId, out EnterpriseUser user);
        bool TryGetUserByEmail(string email, out EnterpriseUser user);
        int UserCount { get; }

        IEnumerable<EnterpriseTeam> Teams { get; }
        bool TryGetTeam(string teamUid, out EnterpriseTeam team);
        int TeamCount { get; }

        Task AddUsersToTeams(string[] emails, string[] teamUids, Action<string> warnings = null);
        Task RemoveUsersFromTeams(string[] emails, string[] teamUids, Action<string> warnings = null);
    }

    public interface IEnterpriseEntity
    {
        long Id { get; }
    }

    public interface IParentNodeEntity
    {
        long ParentNodeId { get; }
    }

    public class EnterpriseNode: IEnterpriseEntity, IParentNodeEntity, IDisplayName
    {
        public long Id { get; internal set; }
        public long ParentNodeId { get; internal set; }
        public string DisplayName { get; set; }
        public ISet<long> Subnodes { get; } = new HashSet<long>();
    }

    public enum UserStatus
    {
        Active,
        Inactive, 
        Locked,
        Blocked,
        Disabled,
    }

    public class EnterpriseUser : IEnterpriseEntity, IParentNodeEntity, IDisplayName
    {
        public long Id { get; internal set; }
        public long ParentNodeId { get; internal set; }
        public string Email { get; set; }
        public string DisplayName { get; set; }
        public UserStatus UserStatus { get; internal set; }
        public ISet<string> Teams { get; } = new HashSet<string>();

    }
    public class EnterpriseTeam : IParentNodeEntity
    {
        public string Uid { get; internal set; }
        public long ParentNodeId { get; internal set; }
        public string Name { get; internal set; }

        public bool RestrictSharing { get; internal set; }
        public bool RestrictEdit { get; internal set; }
        public bool RestrictView { get; internal set; }
        public ISet<long> Users { get; } = new HashSet<long>();
        internal byte[] TeamKey { get; set; }

    }

    public class EnterpriseException : Exception
    {
        public EnterpriseException(string message) : base(message)
        {
        }
    }

}
