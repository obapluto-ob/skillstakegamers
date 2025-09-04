
-- Simple user migration for PostgreSQL
-- Run this after deployment

-- Insert users

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('plutomania', 'obedemoni@gmail.com', 'scrypt:32768:8:1$3MPlwuhXmnjKo0C9$d675bb08404f0381919d0c46480b0612c759817f6ae70726f2d008eea6cf94aa9a8d34b068aee2b6e5c4050be368a56ed7d48e3a7022824a91817e641f27ae6c', 4391.16, '3', '9', '592.0', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('pluto', 'obedemoni153@gmail.com', 'scrypt:32768:8:1$Wa1X8x8bcd7q1bw1$c14e52044bd256e2244598d1c4c0ab217c05eecad6e33e6716050070b2ffb8070ee51c4d19259010deeadc63c78a9bc2dfc92777577fbaa92b0067d012883d0e', 150.0, '5', '1', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('plutot', '0729237055@gamebet.local', 'scrypt:32768:8:1$9q5WPp5UZ3NnTZWB$11c88ee484a2cd1c2ca4cc62850a94464a50d1c6af681b62de3834b43aede3cf45714d18a04c6196ea49cf73aabb55b4efcf55859b2c134a18713a563f31e1fe', 0.0, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('obapluto', '0729237059@gamebet.local', 'scrypt:32768:8:1$aTXJ5Yc76CWzY2rx$94998528896e1372c0d063df51d2ec52e173a701812be0020bc42625b124944b5c13564ece33c6a520510862fe5fe26987627908a86a372229452edcc7a39971', 79.5, '3', '2', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('kasongo', '0729237050@gamebet.local', 'scrypt:32768:8:1$AtQaOoLEpqbc0ed6$30fbedea87ae2ae9ccdb4ef34e13573536cb13051c7256ea40f156c87de77319fe66444320f43abd81f175546de29f0acf8ac7f5db82cb18e29691c42a297cec', 335.0, '2', '3', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('kaleb', '0797656882@gamebet.local', 'scrypt:32768:8:1$KsdwaDMVCoQPXAa4$10fe08447b12b1457637c28152309114e164302490fca27287df82844703b60a5f4f9674d746d2d0b8ff9663b73532aa572d863458a314eefe6ba8735f081734', 1242.5, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('skubii', '0729237051@gamebet.local', 'scrypt:32768:8:1$UMuV6LZvMprniBU1$5a8b15fc9b43cc9023eba8905f3674f02f5cd27b8566c3e26ed5183d5dd24277363e2672fc6a52844dd13dd1774b6c00ef43e3aa879479c919bd2277210bbef5', 0.0, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('test_deposit_user', 'test_deposit_user@test.com', 'test123', 970.0, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('test_withdrawal_user', 'test_withdrawal_user@test.com', 'test123', 0.0, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('test_refund_user', 'test_refund_user@test.com', 'test123', 0.0, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('kasongomustgo', '0729237053@gamebet.local', 'pbkdf2:sha256:600000$DY6uh1tA9DnIdIQh$88db9b7f40273fdf1125dc395401b6255765d72686917891cdc0b1e46437dc1c', 523.5, '2', '1', '212.0', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('kolul', '0789187292@gamebet.local', 'pbkdf2:sha256:600000$DY6uh1tA9DnIdIQh$88db9b7f40273fdf1125dc395401b6255765d72686917891cdc0b1e46437dc1c', 0.0, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('kolu', '0789187291@gamebet.local', 'pbkdf2:sha256:600000$DY6uh1tA9DnIdIQh$88db9b7f40273fdf1125dc395401b6255765d72686917891cdc0b1e46437dc1c', 3099.2400000000002, '1', '', '812.0', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password, balance, phone, referral_code, created_at, wins, losses, total_earnings)
VALUES ('testuser', '0712345678@gamebet.local', 'pbkdf2:sha256:600000$ZNCcRmvMMuAmEX8I$c11454a1f660b1370471924a62507a13383c5c59bb6cc159c2b97d24255d5106', 0.0, '', '', 'NOW()', 0, 0, 0)
ON CONFLICT (username) DO NOTHING;
