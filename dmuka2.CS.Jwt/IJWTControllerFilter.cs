using System;
using System.Collections.Generic;
using System.Text;

namespace dmuka2.CS.Jwt
{
    /// <summary>
    /// If you want to use JWT on request, you should use this Interface your controllers.
    /// <para>
    /// So you can get the authorization datas from the Jwt property.
    /// </para>
    /// </summary>
    public interface IJWTControllerFilter
    {
        /// <summary>
        /// Your authorization datas on the Authentication Header.
        /// </summary>
        Dictionary<string, string> Jwt { get; set; }
    }
}
