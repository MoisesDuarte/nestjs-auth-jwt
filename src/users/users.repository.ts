import { EntityRepository, Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { UserRole } from './user-roles.enum';
import { User } from './user.entity';

import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import {
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import { CredentialsDto } from 'src/auth/dto/credentials.dto';

@EntityRepository(User)
export class UserRepository extends Repository<User> {
  async createUser(
    createUserDto: CreateUserDto,
    role: UserRole,
  ): Promise<User> {
    // ? Fetching payload data
    const { email, name, password } = createUserDto;

    // ? Creating user entity
    const user = this.create();
    user.email = email;
    user.name = name;
    user.role = role;
    user.status = true;

    // ? Encrypting login credentials
    user.confirmationToken = crypto.randomBytes(32).toString('hex');
    user.salt = await bcrypt.genSalt();
    user.password = await this.hashPassword(password, user.salt);

    // ? Trying to save entity
    try {
      await user.save();
      delete user.password;
      delete user.salt;
      return user;
    } catch (error) {
      if (error.code.toString() === '23505') {
        throw new ConflictException('Endereço de email já está em uso');
      } else {
        throw new InternalServerErrorException(
          'Erro ao salvar usuário no banco de dados',
        );
      }
    }
  }

  async checkCredentials(credentialDto: CredentialsDto): Promise<User> {
    // ? Fetching user from database
    const { email, password } = credentialDto;
    const user = await this.findOne({ email, status: true });

    // ? Checking if user is valid
    if (user && (await user.checkPassword(password))) {
      return user;
    } else {
      return null;
    }
  }

  private async hashPassword(password: string, salt: string): Promise<string> {
    return bcrypt.hash(password, salt);
  }
}
