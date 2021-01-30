# QueryArgumentEncryptor

[![NuGet version (SoftCircuits.QueryArgumentEncryptor)](https://img.shields.io/nuget/v/SoftCircuits.QueryArgumentEncryptor.svg?style=flat-square)](https://www.nuget.org/packages/SoftCircuits.QueryArgumentEncryptor/)

```
Install-Package SoftCircuits.QueryArgumentEncryptor
```

`QueryArgumentEncryptor` makes it easy to pass private data as a URL query argument.

When passing data as a query argument in a URL, sometimes that data contains sensitive information that you do not want to expose to the user. In addition, sometimes it is important to ensure that data is not tampered with. For example, if a query argument contained an ID associated with the current user, someone could edit the ID and potentially expose information for another user.

`QueryArgumentEncryptor` solves both issues by converting any number of key/value pairs into a single, encrypted string. The class also computes a checksum on the data. When decrypting the string, all the data is rejected if the checksums do not match.

## Using the Class

`QueryArgumentEncryptor` derives from `Dictionary<string, string>`. So you can add data to it using the `Dictionary` class' methods and properties.

```cs
ArgumentEncryptor args = new ArgumentEncryptor("Password123");
args.Add("Key1", "Value1");
args.Add("Key2", "Value2");
```

Next, use the `EncryptData()` method to compute a checksum on your data and encrypt everything into a single string. By default, the encrypted string will be URL encoded. You can set the `urlEncode` argument to override this.

```cs
string url = string.Format("http://www.mydomain.com?data={0}", encryptor.EncryptData());
```

The page receiving this URL request can then reconstitute the original data from the query argument. (Obviously, the password must match the one used to create the argument.)

```cs
string arg = /* Value of query argument */

// Note: An exception is thrown if the password or data is invalid.
ArgumentEncryptor args = new ArgumentEncryptor("Password123", arg);
// Get some data
string s = args["Key1"];
```
