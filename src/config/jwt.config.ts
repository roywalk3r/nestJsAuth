export const jwtConstants = {
  accessTokenSecret:
    process.env.JWT_ACCESS_SECRET ||
    'MySecure8AccessToken1723456789012345678901SecretKey',
  refreshTokenSecret:
    process.env.JWT_REFRESH_SECRET ||
    'MySecure8RefreshToken1723456789012345678901SecretKey',
  accessTokenExpiration: '60m',
  refreshTokenExpiration: '7d',
};
