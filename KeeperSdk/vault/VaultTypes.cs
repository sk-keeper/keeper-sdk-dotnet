//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk
{
    public interface IVaultData
    {
        IKeeperStorage Storage { get; }
        byte[] ClientKey { get; }

        FolderNode RootFolder { get; }
        IEnumerable<FolderNode> Folders { get; }
        bool TryGetFolder(string folderUid, out FolderNode node);
        
        int RecordCount { get; }
        IEnumerable<PasswordRecord> Records { get; }
        bool TryGetRecord(string recordUid, out PasswordRecord node);

        int SharedFolderCount { get; }
        IEnumerable<SharedFolder> SharedFolders { get; }
        bool TryGetSharedFolder(string sharedFolderUid, out SharedFolder sharedFolder);

        int TeamCount { get; }
        IEnumerable<Team> Teams { get; }
        bool TryGetTeam(string teamUid, out Team team);
    }

    public interface IVaultUi
    {
        Task<bool> Confirmation(string information);
    }

    public class RecordPath
    {
        public string FolderUid { get; set; }
        public string RecordUid { get; set; }
    }

    public interface ISharedFolderRecordOptions
    {
        bool? CanEdit { get; }
        bool? CanShare { get; }
    }

    public interface ISharedFolderUserOptions
    {
        bool? ManageUsers { get; }
        bool? ManageRecords { get; }
    }

    public interface IVault : IVaultData
    {
        IVaultUi VaultUi { get; }
        Task<PasswordRecord> CreateRecord(PasswordRecord record, string folderUid = null);
        Task<PasswordRecord> UpdateRecord(PasswordRecord record);
        Task DeleteRecords(RecordPath[] records);
        Task MoveRecords(RecordPath[] records, string dstFolderUid, bool link = false);
        Task StoreNonSharedData<T>(string recordUid, T nonSharedData) where T : RecordNonSharedDataData;

        Task<FolderNode> CreateFolder<T>(string name, string parentFolderUid = null, T sharedFolderOptions = null) 
            where T: class, ISharedFolderUserOptions, ISharedFolderRecordOptions;
        Task<FolderNode> RenameFolder(string folderUid, string newName);
        Task MoveFolder(string srcFolderUid, string dstFolderUid, bool link = false);
        Task DeleteFolder(string folderUid);
    }

    public interface IVaultSharedFolder
    {
        Task PutUserToSharedFolder(string sharedFolderUid, string userId, UserType userType, ISharedFolderUserOptions options = null);
        Task RemoveUserFromSharedFolder(string sharedFolderUid, string userId, UserType userType);

        Task ChangeRecordInSharedFolder(string sharedFolderUid, string recordUid, ISharedFolderRecordOptions options);
    }

    public class VaultException : Exception
    {
        public VaultException(string message) : base(message)
        {
        }
        public VaultException(string translationKey, string message) : base(message)
        {
            TranslationKey = translationKey;
        }

        public string TranslationKey { get; }
    }

    public class PasswordRecord
    {
        public string Uid { get; set; }
        public bool Owner { get; set; }
        public bool Shared { get; set; }

        public string Title { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }
        public string Link { get; set; }
        public string Notes { get; set; }
        public DateTimeOffset ClientModified { get; internal set; }
        public IList<CustomField> Custom { get; } = new List<CustomField>();
        public IList<AttachmentFile> Attachments { get; } = new List<AttachmentFile>();
        public IList<ExtraField> ExtraFields { get; } = new List<ExtraField>();
        public byte[] RecordKey { get; set; }

        public CustomField DeleteCustomField(string name)
        {
            var cf = Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
            if (cf != null)
            {
                if (Custom.Remove(cf))
                {
                    return cf;
                }
            }

            return null;
        }

        public CustomField SetCustomField(string name, string value)
        {
            var cf = Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
            if (cf == null)
            {
                if (string.IsNullOrEmpty(value))
                {
                    return null;
                }

                cf = new CustomField
                {
                    Name = name
                };
                Custom.Add(cf);
            }
            cf.Value = value;

            return cf;
        }
    }

    public class CustomField
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Type { get; set; }
    }

    public class ExtraField
    {
        public string Id { get; set; }
        public string FieldType { get; set; }
        public string FieldTitle { get; set; }
        public Dictionary<string, object> Custom { get; } = new Dictionary<string, object>();
    }

    public class AttachmentFileThumb
    {
        public string Id { get; internal set; }
        public string Type { get; internal set; }
        public int Size { get; internal set; }
    }

    public class AttachmentFile
    {
        public string Id { get; set; }
        public string Key { get; set; }
        public string Name { get; set; }
        public string Title { get; set; }
        public string Type { get; set; }
        public long Size { get; set; }
        public DateTimeOffset LastModified { get; set; }

        public AttachmentFileThumb[] Thumbnails { get; internal set; }
    }

    public enum UserType
    {
        User = 1,
        Team = 2
    }

    public class SharedFolderPermission
    {
        public string UserId { get; internal set; }
        public UserType UserType { get; internal set; }
        public bool ManageRecords { get; internal set; }
        public bool ManageUsers { get; internal set; }
    }

    public class SharedFolderRecord
    {
        public string RecordUid { get; internal set; }
        public bool CanShare { get; internal set; }
        public bool CanEdit { get; internal set; }
    }

    public class SharedFolder
    {
        public string Uid { get; set; }
        public string Name { get; set; }

        public bool DefaultManageRecords { get; set; }
        public bool DefaultManageUsers { get; set; }
        public bool DefaultCanEdit { get; set; }
        public bool DefaultCanShare { get; set; }

        public List<SharedFolderPermission> UsersPermissions { get; } = new List<SharedFolderPermission>();
        public List<SharedFolderRecord> RecordPermissions { get; } = new List<SharedFolderRecord>();

        public byte[] SharedFolderKey { get; set; }
    }

    public class TeamInfo
    {
        public string TeamUid { get; set; }
        public string Name { get; set; }
    }

    public class Team: TeamInfo
    {
        internal Team()
        {
        }

        internal Team(IEnterpriseTeam et, byte[] teamKey)
        {
            TeamKey = teamKey;
            var pk = et.TeamPrivateKey.Base64UrlDecode();
            TeamPrivateKey = CryptoUtils.LoadPrivateKey(CryptoUtils.DecryptAesV1(pk, teamKey));
            TeamUid = et.TeamUid;
            Name = et.Name;
            RestrictEdit = et.RestrictEdit;
            RestrictShare = et.RestrictShare;
            RestrictView = et.RestrictView;
        }

        public bool RestrictEdit { get; set; }
        public bool RestrictShare { get; set; }
        public bool RestrictView { get; set; }

        public byte[] TeamKey { get; set; }
        public RsaPrivateCrtKeyParameters TeamPrivateKey { get; internal set; }
    }

    public enum FolderType
    {
        UserFolder,
        SharedFolder,
        SharedFolderFolder
    }


    public class FolderNode
    {
        public string ParentUid { get; internal set; }
        public string FolderUid { get; internal set; }
        public string SharedFolderUid { get; internal set; }
        public FolderType FolderType { get; internal set; } = FolderType.UserFolder;
        public string Name { get; internal set; }
        public IList<string> Subfolders { get; } = new List<string>();
        public IList<string> Records { get; } = new List<string>();
    }

    public interface IRecordAccessPath
    {
        string RecordUid { get; }
        string SharedFolderUid { get; set; }
        string TeamUid { get; set; }
    }

    public interface ISharedFolderAccessPath
    {
        string SharedFolderUid { get; set; }
        string TeamUid { get; set; }
    }

    public static class VaultTypeExtensions
    {
        internal static readonly IDictionary<FolderType, string> FolderTypes = new Dictionary<FolderType, string>
        {
            {FolderType.UserFolder, "user_folder"},
            {FolderType.SharedFolder, "shared_folder"},
            {FolderType.SharedFolderFolder, "shared_folder_folder"},
        };

        public static string GetFolderTypeText(this FolderType folderType)
        {
            return FolderTypes[folderType];
        }
    }
}