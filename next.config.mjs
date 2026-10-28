/** @type {import('next').NextConfig} */
const nextConfig = {
  async redirects() {
    return [
      {
        source: '/shopshield.html',
        destination: '/',
        permanent: true
      }
    ];
  }
};

export default nextConfig;
