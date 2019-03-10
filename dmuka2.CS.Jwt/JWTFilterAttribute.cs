using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace dmuka2.CS.Jwt
{
    /// <summary>
    /// If you add this attribute to your action, it always check the Authentication Header by JWT.
    /// <para>
    /// If it's not valid, response will return 401.
    /// </para>
    /// </summary>
    public abstract class JWTFilterAttribute : ActionFilterAttribute
    {
        #region Constructors
        #endregion

        #region Variables
        public virtual JWTToken Token { get; set; }
        public Dictionary<string, string> Jwt { get; set; }
        #endregion

        public virtual bool JwtDecrypted(ActionExecutingContext context) => true;

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            StringValues header;
            if (context.HttpContext.Request.Headers.TryGetValue("Authorization", out header) == false)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            try
            {
                var bearerToken = header[0].Substring(7);
                ((IJWTControllerFilter)context.Controller).Jwt = this.Jwt = this.Token.ReadWithValid(bearerToken, DateTime.UtcNow);
                if (JwtDecrypted(context) == true)
                    base.OnActionExecuting(context);
                else
                    throw new Exception("JwtDecrypted was fail!");
            }
            catch (Exception ex)
            {
                context.Result = new UnauthorizedResult();
            }
        }
    }
}
