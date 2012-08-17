using System;

namespace MSMQSecurity
{
    [Flags]
    public enum MQQUEUEACCESSMASK
    {
        MQSEC_DELETE_MESSAGE = 0x00000001,
        MQSEC_PEEK_MESSAGE = 0x00000002,
        MQSEC_WRITE_MESSAGE = 0x00000004,
        MQSEC_DELETE_JOURNAL_MESSAGE = 0x00000008,
        MQSEC_SET_QUEUE_PROPERTIES = 0x00000010,
        MQSEC_GET_QUEUE_PROPERTIES = 0x00000020,
        MQSEC_DELETE_QUEUE = 0x00010000,
        MQSEC_GET_QUEUE_PERMISSIONS = 0x00020000,
        MQSEC_CHANGE_QUEUE_PERMISSIONS = 0x00040000,
        MQSEC_TAKE_QUEUE_OWNERSHIP = 0x00080000,
        MQSEC_RECEIVE_MESSAGE = (MQSEC_DELETE_MESSAGE
                               | MQSEC_PEEK_MESSAGE),
        MQSEC_RECEIVE_JOURNAL_MESSAGE = (MQSEC_DELETE_JOURNAL_MESSAGE
                                       | MQSEC_PEEK_MESSAGE),
        MQSEC_QUEUE_GENERIC_READ = (MQSEC_GET_QUEUE_PROPERTIES
                                  | MQSEC_GET_QUEUE_PERMISSIONS
                                  | MQSEC_RECEIVE_MESSAGE
                                  | MQSEC_RECEIVE_JOURNAL_MESSAGE),
        MQSEC_QUEUE_GENERIC_WRITE = (MQSEC_GET_QUEUE_PROPERTIES
                                   | MQSEC_GET_QUEUE_PERMISSIONS
                                   | MQSEC_WRITE_MESSAGE),
        MQSEC_QUEUE_GENERIC_ALL = (MQSEC_RECEIVE_MESSAGE
                                 | MQSEC_RECEIVE_JOURNAL_MESSAGE
                                 | MQSEC_WRITE_MESSAGE
                                 | MQSEC_SET_QUEUE_PROPERTIES
                                 | MQSEC_GET_QUEUE_PROPERTIES
                                 | MQSEC_DELETE_QUEUE
                                 | MQSEC_GET_QUEUE_PERMISSIONS
                                 | MQSEC_CHANGE_QUEUE_PERMISSIONS
                                 | MQSEC_TAKE_QUEUE_OWNERSHIP)
    };

    [Flags]
    internal enum SecurityInformation : uint
    {
        Owner = 0x00000001,
        Group = 0x00000002,
        Dacl = 0x00000004,
        Sacl = 0x00000008,
        ProtectedDacl = 0x80000000,
        ProtectedSacl = 0x40000000,
        UnprotectedDacl = 0x20000000,
        UnprotectedSacl = 0x10000000
    }

    internal enum ACL_INFORMATION_CLASS
    {
        AclRevisionInformation = 1,
        AclSizeInformation
    }
}