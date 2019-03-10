using Microsoft.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace dmuka2.CS.Jwt
{
    /// <summary>
    /// JWT Token creater and reader. 
    /// <para>
    /// You can also create with valid or read with valid.
    /// </para>
    /// </summary>
    public class JWTToken
    {
        #region Variables
        SymmetricSecurityKey _key = null;
        SigningCredentials _credential = null;
        JwtSecurityTokenHandler _tokenHandler = null;
        #endregion

        #region Constructors
        public JWTToken(string key, string algorithm = null)
        {
            this._tokenHandler = new JwtSecurityTokenHandler();
            this._key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
            this._credential = new SigningCredentials(this._key, algorithm ?? SecurityAlgorithms.HmacSha256Signature);
        }
        #endregion

        #region Methods
        public string CreateWithValid(DateTime expireDateUTC, params Claim[] claims)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expireDateUTC,
                SigningCredentials = this._credential
            };
            var token = this._tokenHandler.CreateToken(tokenDescriptor);
            return this._tokenHandler.WriteToken(token);
        }

        public string CreateWithoutValid(params Claim[] claims)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims)
            };
            var token = this._tokenHandler.CreateToken(tokenDescriptor);
            return this._tokenHandler.WriteToken(token);
        }

        public Dictionary<string, string> ReadWithValid(string token, DateTime expireDateUTC)
        {
            SecurityToken securityToken;
            var deserialize = this._tokenHandler.ValidateToken(token, new TokenValidationParameters()
            {
                IssuerSigningKey = this._key,
                ValidateIssuerSigningKey = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = true,
                LifetimeValidator = (DateTime? notBefore, DateTime? expires, SecurityToken st, TokenValidationParameters vp) => expireDateUTC < expires
            }, out securityToken);

            Dictionary<string, string> result = new Dictionary<string, string>();
            foreach (var item in deserialize.Claims)
                result.Add(item.Type, item.Value);
            return result;
        }

        public Dictionary<string, string> ReadWithoutValid(string token)
        {
            var deserialize = this._tokenHandler.ReadJwtToken(token);

            Dictionary<string, string> result = new Dictionary<string, string>();
            foreach (var item in deserialize.Claims)
                result.Add(item.Type, item.Value);
            return result;
        }
        #endregion
    }
}
