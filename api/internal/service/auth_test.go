package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RintaroNasu/routetap/api/internal/models"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type fakeAuthRepo struct {
	createUser  func(ctx context.Context, user *models.User) error
	findByEmail func(ctx context.Context, email string) (*models.User, error)
	findByID    func(ctx context.Context, id uint) (*models.User, error)
}

func (f *fakeAuthRepo) CreateUser(ctx context.Context, user *models.User) error {
	if f.createUser == nil {
		return nil
	}
	return f.createUser(ctx, user)
}

func (f *fakeAuthRepo) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if f.findByEmail == nil {
		return nil, nil
	}
	return f.findByEmail(ctx, email)
}

func (f *fakeAuthRepo) FindUserByID(ctx context.Context, id uint) (*models.User, error) {
	if f.findByID == nil {
		return nil, nil
	}
	return f.findByID(ctx, id)
}

type fakeJWTManager struct {
	generateToken func(userID uint) (string, error)
}

func (f *fakeJWTManager) GenerateToken(userID uint) (string, error) {
	if f.generateToken == nil {
		return "", nil
	}
	return f.generateToken(userID)
}

func TestAuthService_Signup(t *testing.T) {
	type input struct {
		name     string
		email    string
		password string
	}

	tooLongPassword := strings.Repeat("a", 73)

	tests := []struct {
		name          string
		in            input
		repo          fakeAuthRepo
		jwtManager    fakeJWTManager
		wantErr       error
		errContains   string
		wantToken     string
		assertCreated func(t *testing.T, user *models.User)
	}{
		{
			name: "【正常系】ユーザーを新規登録できること",
			in:   input{name: "  Taro  ", email: "  TARO@EXAMPLE.COM  ", password: "pass1234"},
			repo: fakeAuthRepo{
				createUser: func(ctx context.Context, user *models.User) error {
					user.ID = 1
					return nil
				},
			},
			jwtManager: fakeJWTManager{
				generateToken: func(userID uint) (string, error) {
					require.Equal(t, uint(1), userID)
					return "signup-token", nil
				},
			},
			wantToken: "signup-token",
			assertCreated: func(t *testing.T, user *models.User) {
				require.Equal(t, "Taro", user.Name)
				require.Equal(t, "taro@example.com", user.Email)
				require.NotEmpty(t, user.PasswordHash)
				require.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("pass1234")))
			},
		},
		{
			name:    "【異常系】email未入力の場合は ErrEmailRequired を返すこと",
			in:      input{email: "", password: "pass1234"},
			wantErr: ErrEmailRequired,
		},
		{
			name:    "【異常系】password未入力の場合は ErrPasswordRequired を返すこと",
			in:      input{email: "taro@example.com", password: ""},
			wantErr: ErrPasswordRequired,
		},
		{
			name:    "【異常系】email形式不正の場合は ErrInvalidEmailFormat を返すこと",
			in:      input{email: "invalid-email", password: "pass1234"},
			wantErr: ErrInvalidEmailFormat,
		},
		{
			name:        "【異常系】bcrypt hash生成失敗時は generate password hash エラーになること",
			in:          input{email: "taro@example.com", password: tooLongPassword},
			errContains: "generate password hash",
		},
		{
			name: "【異常系】email重複時は ErrEmailAlreadyExists を返すこと",
			in:   input{email: "taro@example.com", password: "pass1234"},
			repo: fakeAuthRepo{
				createUser: func(ctx context.Context, user *models.User) error {
					return gorm.ErrDuplicatedKey
				},
			},
			wantErr: ErrEmailAlreadyExists,
		},
		{
			name: "【異常系】DB保存失敗時は create user エラーになること",
			in:   input{email: "taro@example.com", password: "pass1234"},
			repo: fakeAuthRepo{
				createUser: func(ctx context.Context, user *models.User) error {
					return errors.New("insert failed")
				},
			},
			errContains: "create user",
		},
		{
			name: "【異常系】JWT生成失敗時は generate token エラーになること",
			in:   input{email: "taro@example.com", password: "pass1234"},
			repo: fakeAuthRepo{
				createUser: func(ctx context.Context, user *models.User) error {
					user.ID = 1
					return nil
				},
			},
			jwtManager: fakeJWTManager{
				generateToken: func(userID uint) (string, error) {
					return "", errors.New("sign failed")
				},
			},
			errContains: "generate token",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var createdUser *models.User
			repo := tt.repo
			if repo.createUser != nil {
				original := repo.createUser
				repo.createUser = func(ctx context.Context, user *models.User) error {
					createdUser = &models.User{
						ID:           user.ID,
						Name:         user.Name,
						Email:        user.Email,
						PasswordHash: user.PasswordHash,
					}
					err := original(ctx, user)
					createdUser.ID = user.ID
					return err
				}
			}

			jwtManager := tt.jwtManager
			if jwtManager.generateToken == nil {
				jwtManager.generateToken = func(userID uint) (string, error) {
					return "default-token", nil
				}
			}

			svc := NewAuthService(&repo, &jwtManager)
			got, err := svc.Signup(context.Background(), SignupInput{
				Name:     tt.in.name,
				Email:    tt.in.email,
				Password: tt.in.password,
			})

			switch {
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
			case tt.errContains != "":
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				require.Nil(t, got)
			default:
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.wantToken, got.Token)
				if tt.assertCreated != nil {
					require.NotNil(t, createdUser)
					tt.assertCreated(t, createdUser)
				}
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	hash := func(pw string) string {
		b, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		return string(b)
	}

	type input struct {
		email    string
		password string
	}

	tests := []struct {
		name        string
		in          input
		repo        fakeAuthRepo
		jwtManager  fakeJWTManager
		wantErr     error
		errContains string
		wantToken   string
	}{
		{
			name: "【正常系】正しい認証情報でログインできること",
			in:   input{email: "  TARO@EXAMPLE.COM ", password: "pass1234"},
			repo: fakeAuthRepo{
				findByEmail: func(ctx context.Context, email string) (*models.User, error) {
					require.Equal(t, "taro@example.com", email)
					return &models.User{ID: 1, Email: email, PasswordHash: hash("pass1234")}, nil
				},
			},
			jwtManager: fakeJWTManager{
				generateToken: func(userID uint) (string, error) {
					require.Equal(t, uint(1), userID)
					return "login-token", nil
				},
			},
			wantToken: "login-token",
		},
		{
			name:    "【異常系】email未入力の場合は ErrEmailRequired を返すこと",
			in:      input{email: "", password: "pass1234"},
			wantErr: ErrEmailRequired,
		},
		{
			name:    "【異常系】password未入力の場合は ErrPasswordRequired を返すこと",
			in:      input{email: "taro@example.com", password: ""},
			wantErr: ErrPasswordRequired,
		},
		{
			name:    "【異常系】email形式不正の場合は ErrInvalidEmailFormat を返すこと",
			in:      input{email: "invalid-email", password: "pass1234"},
			wantErr: ErrInvalidEmailFormat,
		},
		{
			name: "【異常系】存在しないemailの場合は ErrInvalidCredentials を返すこと",
			in:   input{email: "taro@example.com", password: "pass1234"},
			repo: fakeAuthRepo{
				findByEmail: func(ctx context.Context, email string) (*models.User, error) {
					return nil, gorm.ErrRecordNotFound
				},
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name: "【異常系】password不一致の場合は ErrInvalidCredentials を返すこと",
			in:   input{email: "taro@example.com", password: "wrongpass"},
			repo: fakeAuthRepo{
				findByEmail: func(ctx context.Context, email string) (*models.User, error) {
					return &models.User{ID: 1, Email: email, PasswordHash: hash("pass1234")}, nil
				},
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name: "【異常系】DB検索失敗時は find user by email エラーになること",
			in:   input{email: "taro@example.com", password: "pass1234"},
			repo: fakeAuthRepo{
				findByEmail: func(ctx context.Context, email string) (*models.User, error) {
					return nil, errors.New("select failed")
				},
			},
			errContains: "find user by email",
		},
		{
			name: "【異常系】bcrypt compare異常時は compare password hash エラーになること",
			in:   input{email: "taro@example.com", password: "pass1234"},
			repo: fakeAuthRepo{
				findByEmail: func(ctx context.Context, email string) (*models.User, error) {
					return &models.User{ID: 1, Email: email, PasswordHash: "invalid-hash"}, nil
				},
			},
			errContains: "compare password hash",
		},
		{
			name: "【異常系】JWT生成失敗時は generate token エラーになること",
			in:   input{email: "taro@example.com", password: "pass1234"},
			repo: fakeAuthRepo{
				findByEmail: func(ctx context.Context, email string) (*models.User, error) {
					return &models.User{ID: 1, Email: email, PasswordHash: hash("pass1234")}, nil
				},
			},
			jwtManager: fakeJWTManager{
				generateToken: func(userID uint) (string, error) {
					return "", errors.New("sign failed")
				},
			},
			errContains: "generate token",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			jwtManager := tt.jwtManager
			if jwtManager.generateToken == nil {
				jwtManager.generateToken = func(userID uint) (string, error) {
					return "default-token", nil
				}
			}

			svc := NewAuthService(&tt.repo, &jwtManager)
			got, err := svc.Login(context.Background(), LoginInput{
				Email:    tt.in.email,
				Password: tt.in.password,
			})

			switch {
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
			case tt.errContains != "":
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				require.Nil(t, got)
			default:
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.wantToken, got.Token)
			}
		})
	}
}

func TestAuthService_Me(t *testing.T) {
	now := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		userID      uint
		repo        fakeAuthRepo
		want        *MeResponse
		wantErr     error
		errContains string
	}{
		{
			name:   "【正常系】ログインユーザーを取得できること",
			userID: 3,
			repo: fakeAuthRepo{
				findByID: func(ctx context.Context, id uint) (*models.User, error) {
					return &models.User{
						ID:        id,
						Name:      "Taro",
						Email:     "taro@example.com",
						CreatedAt: now,
						UpdatedAt: now.Add(time.Hour),
					}, nil
				},
			},
			want: &MeResponse{
				ID:        3,
				Name:      "Taro",
				Email:     "taro@example.com",
				CreatedAt: now.Format(time.RFC3339),
				UpdatedAt: now.Add(time.Hour).Format(time.RFC3339),
			},
		},
		{
			name:   "【異常系】ユーザーが存在しない場合は ErrUserNotFound を返すこと",
			userID: 3,
			repo: fakeAuthRepo{
				findByID: func(ctx context.Context, id uint) (*models.User, error) {
					return nil, gorm.ErrRecordNotFound
				},
			},
			wantErr: ErrUserNotFound,
		},
		{
			name:   "【異常系】DB検索失敗時は find user by id エラーになること",
			userID: 3,
			repo: fakeAuthRepo{
				findByID: func(ctx context.Context, id uint) (*models.User, error) {
					return nil, errors.New("select failed")
				},
			},
			errContains: "find user by id",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAuthService(&tt.repo, &fakeJWTManager{})
			got, err := svc.Me(context.Background(), tt.userID)

			switch {
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
			case tt.errContains != "":
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				require.Nil(t, got)
			default:
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.want, got)
			}
		})
	}
}
