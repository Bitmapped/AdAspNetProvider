using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Elmah;

namespace AdAspNetProvider.Logging
{
    internal static class Log
    {
        private static bool? elmahAvailable = null;

        /// <summary>
        /// Verify that Elmah exists and is ready for use.
        /// </summary>
        /// <returns></returns>
        private static bool ElmahExists()
        {
            // If elmahAvailable, return true.
            if ((Log.elmahAvailable.HasValue) && (Log.elmahAvailable.Value == true))
            {
                return true;
            }

            // Check if elmah can be loaded.
            try
            {
                var assemblyName = AssemblyName.GetAssemblyName("Elmah.dll");
            }
            catch
            {
                // Could not load Elmah.
                Log.elmahAvailable = false;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Log an exception with Elmah.
        /// </summary>
        /// <param name="e">Exception to log.</param>
        /// <returns>True/false if exception was logged.</returns>
        internal static bool LogError(Exception e)
        {
            // Verify that Elmah exists.
            if (Log.ElmahExists() == false)
            {
                return false;
            }

            // Attempt to log error.
            try
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(e);
            }
            catch
            {
                // Could not log error.
                return false;
            }

            // Assume error was successfully logged.
            return true;
        }


    }
}
