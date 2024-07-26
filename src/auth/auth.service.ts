import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDTO, RegisterUserDTO } from './dto';
import { RpcException } from '@nestjs/microservices';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    
    private readonly logger = new Logger('AuthService');

    constructor(private readonly jwtService: JwtService){
        super();
    }
    
    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJWT(payload: JwtPayload){
        return this.jwtService.sign(payload);
    }

    async registerUser(registerUserDTO: RegisterUserDTO){
        const {email, name, password} = registerUserDTO;
        try {
            
            const user = await this.user.findUnique({
                where:{
                    email: email,
                }
            });
            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                })
            }

            const newUser = await this.user.create({
                data:{
                    email:email,
                    password: bcrypt.hashSync(password,10),
                    name:name,
                }
            });

            const { password: _, ...rest} = newUser;

            return {
                user: rest,
                token: await this.signJWT(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })            
        }
    }

    async loginUser(loginUserDTO: LoginUserDTO){
        const {email, password} = loginUserDTO;
        try {
            
            const user = await this.user.findUnique({
                where:{ email}
            });
            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid Credential.'
                })
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);
            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid Credential!'
                })
            }
            const { password: _, ...rest} = user;

            return {
                user: rest,
                token: await this.signJWT(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })            
        }
    }

    async verifyToken(token: string){
        try {
            const {sub, iat, exp, ...user} = this.jwtService.verify(token,{
                secret: envs.jwtSecret,
            });

            return {
                user: user,
                token: await this.signJWT(user),
            }
        } catch (error) {
            console.log(error);
            throw new RpcException({
                status: 401,
                message: 'Invalid Token...'
            })
        }
    }
}
