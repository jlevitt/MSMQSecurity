namespace MSMQSecurity
{
    public class QueuePath
    {
        private const string QueuePathFormat = @"Direct=OS:{0}\Private$\{1}";

        private string computerName;
        private string queueName;

        public QueuePath(string computerName, string queueName)
        {
            this.computerName = computerName;
            this.queueName = queueName;
        }

        public override string ToString()
        {
            return string.Format(QueuePathFormat, computerName, queueName);
        }
    }
}
