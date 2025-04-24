import { describe, it, expect } from 'vitest';
import { PasswordService } from '../services/password.services';

const passwordService = PasswordService.getInstance();

describe('PasswordService.isPasswordValid', () => {
  it('should accept a valid password', () => {
    expect(passwordService.isPasswordValid('Password123!')).toBe(true);
    expect(passwordService.isPasswordValid('Abcdef1!')).toBe(true);
    expect(passwordService.isPasswordValid('A1b2c3d4!')).toBe(true);
  });

  it('should reject passwords that are too short', () => {
    expect(passwordService.isPasswordValid('Abc1!')).toBe(false);
    expect(passwordService.isPasswordValid('A1b!')).toBe(false);
  });

  it('should reject passwords without uppercase', () => {
    expect(passwordService.isPasswordValid('password123!')).toBe(false);
  });

  it('should reject passwords without lowercase', () => {
    expect(passwordService.isPasswordValid('PASSWORD123!')).toBe(false);
  });

  it('should reject passwords without digit', () => {
    expect(passwordService.isPasswordValid('Password!')).toBe(false);
  });

  it('should reject passwords without special character', () => {
    expect(passwordService.isPasswordValid('Password123')).toBe(false);
  });

  it('should reject empty or null passwords', () => {
    expect(passwordService.isPasswordValid('')).toBe(false);
    // @ts-expect-error
    expect(passwordService.isPasswordValid(null)).toBe(false);
    // @ts-expect-error
    expect(passwordService.isPasswordValid(undefined)).toBe(false);
  });
});
