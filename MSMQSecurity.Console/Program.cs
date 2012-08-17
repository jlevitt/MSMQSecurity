using System;

namespace MSMQSecurity
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var queuePath = new QueuePath(".", "queue");

            try
            {
                var aceMask = MSMQSecurity.GetAccessMask(queuePath, @"username");

                Console.WriteLine(aceMask);
                if ((aceMask & MQQUEUEACCESSMASK.MQSEC_RECEIVE_MESSAGE) == MQQUEUEACCESSMASK.MQSEC_RECEIVE_MESSAGE)
                {
                    Console.WriteLine("Has receive access");
                }
                else
                {
                    Console.WriteLine("Doesn't have receive access");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadKey();
        }
    }
}
