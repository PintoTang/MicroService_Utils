using Microsoft.Extensions.DependencyInjection;
using Utils.Lib.Files;
using Utils.Lib.Randoms;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;

namespace Utils.Lib
{
    /// <summary>
    /// 系统扩展 - 基础设施
    /// </summary>
    public static partial class Extensions
    {
        /// <summary>
        /// 注册Util基础设施服务
        /// </summary>
        /// <param name="services">服务集合</param>
        public static IServiceCollection AddUtil(this IServiceCollection services)
        {
            // 添加文件操作
            services.AddSingleton<IFengFileProvider, FengFileProvider>();
            // 添加随机ID
            services.AddSingleton<IRandomGenerator, GuidRandomGenerator>();
            // 值设置
            Helpers.Web.HttpContextAccessor = services.BuildServiceProvider().GetRequiredService<IHttpContextAccessor>();
            Helpers.Web.Environment = services.BuildServiceProvider().GetRequiredService<IHostingEnvironment>();
            return services;
        }
    }
}
