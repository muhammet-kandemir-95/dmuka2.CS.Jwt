using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Claims;

namespace dmuka2.CS.Jwt.MSTest
{
    [TestClass]
    public class JWTTokenTests
    {
        [TestMethod]
        public void Normal()
        {
            string userId = "MyPrivateUserId";
            string userName = "MySpecialUserName";

            JWTToken jwt = new JWTToken("MuhammedKandemir");

            var token = jwt.CreateWithoutValid(
                new Claim(nameof(userId), userId),
                new Claim(nameof(userName), userName));

            var deserialize = jwt.ReadWithoutValid(token);
            Assert.AreEqual(deserialize[nameof(userId)], userId);
            Assert.AreEqual(deserialize[nameof(userName)], userName);
        }

        [TestMethod]
        public void Valid()
        {
            string userId = "MyPrivateUserId";
            string userName = "MySpecialUserName";

            JWTToken jwt = new JWTToken("MuhammedKandemir");

            var token = jwt.CreateWithValid(DateTime.UtcNow.AddDays(7),
                new Claim(nameof(userId), userId),
                new Claim(nameof(userName), userName));

            var deserialize = jwt.ReadWithValid(token, DateTime.UtcNow);
            Assert.AreEqual(deserialize[nameof(userId)], userId);
            Assert.AreEqual(deserialize[nameof(userName)], userName);
        }

        [TestMethod]
        public void ValidWithException()
        {
            string userId = "MyPrivateUserId";
            string userName = "MySpecialUserName";

            JWTToken jwt = new JWTToken("MuhammedKandemir");

            var token = jwt.CreateWithValid(DateTime.UtcNow.AddDays(7),
                new Claim(nameof(userId), userId),
                new Claim(ClaimTypes.Name, userName));

            try
            {
                jwt.ReadWithValid(token, DateTime.UtcNow.AddDays(-1));
                Assert.Fail();
            }
            catch { }
        }
    }
}
