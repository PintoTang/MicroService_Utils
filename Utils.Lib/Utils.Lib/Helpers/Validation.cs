using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Utils.Lib.Helpers
{
    /// <summary>
    /// 验证操作
    /// </summary>
    public class Validation
    {
        /// <summary>
        /// 是否数字
        /// </summary>
        /// <param name="input">输入值</param>        
        public static bool IsNumber(string input)
        {
            if (input.IsEmpty())
                return false;
            const string pattern = @"^(-?\d*)(\.\d+)?$";
            return Regex.IsMatch(input, pattern);
        }

        /// <summary>
        /// 验证
        /// </summary>
        /// <param name="obj">验证目标</param>
        /// <param name="data">上下文数据</param>
        public static void Validate(object obj, Dictionary<object, object> data)
        {
            var validationContext = new ValidationContext(obj, data);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(obj, validationContext, results, true);

            if (!isValid)
            {
                throw new ArgumentNullException(results[0].ErrorMessage);
            }
        }
    }
}
