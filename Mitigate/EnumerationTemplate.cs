using Mitigate.Utils;
using Mitigate.Helper;


namespace Mitigate.Enumerations
{
    //No limitations on the enumeration name. Just need to be unique.
    class ENUMERATION_NAME : Enumeration
    {
        public override string Name => "USER-FRIENDLY NAME FOR THE ENUMERATION";
        public override string MitigationType => MitigationTypes.SELECT_THE_APPROPRIATE_TYPE;
        public override string MitigationDescription => "DESCRIPTION OF THE MITIGATION THIS ENUMERATION IS CHECKING FOR";
        public override string EnumerationDescription => "DESCRIPTION OF WHAT THIS ENUMERATION CHECKS FOR";
        
        // Add all the technique ids that this enumeration addresses
        public override string[] Techniques => new string[]
        {
            "T1234.123",
            "T1235",
            "..."
        }

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // All the enumeration logic goes here
            //
            // The context argument contains some information around the context Mitig&te is executed under
            //      context.UserToCheck returns a UserPrincipal class for the user the checks are performed for
            //      context.UserToCheckSIDs returns a list of strings containing all the SIDs for the user the checks are performed for. This includes group sids
            //      context.Arguments returns an object with all the command line parameters passed to Mitig&te when executed
            //      context.IsDomainJoined returns a boolean on whether the machine running Mitig&te is domain joined

            // Some basic functionality is provided by the static helper class in .\Utils\Helper.cs
            //
            //      REGISTRY HELPERS
            //      Helper.GetRegValue(string hive, string path, string value) => Get the value of a registry key in string format
            //      Helper.GetRegValues(string hive, string path, string value) => Get the values of all registries in the specified hive and path
            //      Helper.GetRegValueBytes(string hive, string path, string value) => Get the value of a registry key in byte format
            //      Helper.GetRegSubkeys(string hive, string path) => Get all the subkey names under the specified hive and path
            //      Helper.RegExists(string hive, string path, string value) => Check if the registry exists
            //
            //      PERMISSION HELPERS
            //      Helper.RegWritePermissions(string hive, string path, List<string> SIDs) => Check if any of the SIDs in the list has write permission on the specified hive and path. Normally used with context.UserToCheckSIDs.
            //      Helper.FileWritePermissions(string FilePath, List<string> SIDs) => Check if any of the SIDs in the list has write permission on the specified file. Normally used with context.UserToCheckSIDs.
            //      Helper.DirectoryRightPermissions(string DirectoryPath, List<string> SIDs) => Check if any of the SIDs in the list has write permission on the specified directory.  Normally used with context.UserToCheckSIDs.
            //      
            //      SERVICES HELPERS
            //      Helper.GetServiceConfig(string ServiceName) => returns the start up type for the service specified
            //      Helper.IsServiceRunning(string ServiceName) => returns a boolean denoting whether the service specified is running
            //
            // In addition to the generic helper class, more specific functionality is provided by class tailored to individual Windows mechanisms"
            //      AppLockerUtils => Allows us to query the status of AppLocker on the machine
            //      OfficeUtils => To enumerate the status of security mechanisms relating to Office
            //      SoftwareRestrictionUtils => To enumerate the status of Software Restriction Policies on the machine
            //      SystemUtils and UserUtils => These will be eventually transitioned into standalone enumeration classes just like this one.


            // Example below. Pulled from .\Enumerations\BehaviorPreventionOnEndpoint\ASRObfuscated.cs
            var RelevantRules = new Dictionary<string, string>()
            {
                {"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC","Block execution of potentially obfuscated scripts"},
            };
            foreach (var rule in RelevantRules)
            {
                yield return new BooleanConfig(rule.Value, ASRUtils.IsRuleEnabled(rule.Key));
                // Return a
                //  - BooleanConfig(string Info, bool Result) for boolean enumerations i.e. it's either true of false
                //  - ConfigurationDetected(string ConfigurationName, string value, bool result = true, string condition=null) for enumerations checking
                //    whether a configuration is within good limits. See BITSJobLifetime.cs
                //  - DisabledFeature(string Info, bool IsDisabled) for enumerations checking if a feature is disabled. See DCOM.cs
                //  - NotApplicable(string Info) if the enumeration is not applicable for the system. Example Office enumerations if office is not installed
                //  - ToolBlocked(string Tool, bool IsBlocked, string Control) for enumerations relating to application whitelisting. See ExecutionPrevention enumerations
                //  - ToolDetected(string Tool) for enumerations checking if a tool is present on the system. See Antivirus.cs.

            }
        }
}
