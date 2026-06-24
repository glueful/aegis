<?php

namespace Glueful\Extensions\Aegis\Repositories;

use Glueful\Repository\BaseRepository;
use Glueful\Extensions\Aegis\Models\UserRole;
use Glueful\Helpers\Utils;

/**
 * User Role Repository
 *
 * Handles user-role assignments and queries
 *
 * Features:
 * - Scoped role assignments
 * - Temporal role management
 * - Role hierarchy traversal
 * - Assignment tracking
 */
class UserRoleRepository extends BaseRepository
{
    protected string $table = 'user_roles';
    protected array $defaultFields = [
        'uuid', 'user_uuid', 'role_uuid', 'scope',
        'granted_by', 'expires_at', 'created_at'
    ];
    protected bool $hasUpdatedAt = false;

    // Static cache to prevent duplicate queries across all instances within a single request.
    // Deliberately the ONLY in-process cache layer: every repository instance (provider,
    // services, controllers) shares it, so invalidation in one place reaches them all.
    /** @var array<string, list<UserRole>> */
    private static array $globalUserRolesCache = [];

    /**
     * Drop every cached role list for one user (all scopes). Must be called
     * whenever the user's role assignments change, or stale roles stay
     * effective for the rest of the process (request, worker, or queue run).
     */
    public static function forgetUserGlobalCache(string $userUuid): void
    {
        foreach (array_keys(self::$globalUserRolesCache) as $cacheKey) {
            if (str_starts_with($cacheKey, $userUuid . '_')) {
                unset(self::$globalUserRolesCache[$cacheKey]);
            }
        }
    }

    public static function flushGlobalCache(): void
    {
        self::$globalUserRolesCache = [];
    }

    public function getTableName(): string
    {
        return $this->table;
    }

    public function create(array $data): string
    {
        if (!isset($data['uuid'])) {
            $data['uuid'] = Utils::generateNanoID();
        }

        $success = $this->db->table($this->table)->insert($data);

        if (!$success) {
            throw new \RuntimeException('Failed to create user role');
        }

        return $data['uuid'];
    }

    /**
     * @param array<string, mixed> $data
     */
    public function createUserRole(array $data): ?UserRole
    {
        $uuid = $this->create($data);
        return $this->findUserRoleByUuid($uuid);
    }

    public function findUserRoleByUuid(string $uuid): ?UserRole
    {
        $result = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['uuid' => $uuid])
            ->limit(1)
            ->get();

        return $result ? new UserRole($result[0]) : null;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function update(string $uuid, array $data): bool
    {
        return (bool) $this->db->table($this->table)->where(['uuid' => $uuid])->update($data);
    }

    public function delete(string $uuid): bool
    {
        return (bool) $this->db->table($this->table)->where(['uuid' => $uuid])->delete();
    }

    /**
     * @param array<string, mixed> $filters
     * @return list<UserRole>
     */
    public function findByUser(string $userUuid, array $filters = []): array
    {
        $query = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['user_uuid' => $userUuid]);

        if (isset($filters['role_uuid'])) {
            $query->where(['role_uuid' => $filters['role_uuid']]);
        }

        if (isset($filters['active_only']) && $filters['active_only']) {
            $currentTime = $this->db->getDriver()->formatDateTime();
            $query->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });
        }

        $query->orderBy(['created_at' => 'DESC']);

        $results = $query->get();
        return array_map(fn($row) => new UserRole($row), $results);
    }

    /**
     * Batch-load each user's active role {uuid,name,slug} list in ONE query (no N+1). Excludes
     * soft-deleted roles and expired assignments. Keyed by user_uuid; users with no roles are absent.
     *
     * @param list<string> $userUuids
     * @return array<string, list<array{uuid: string, name: string, slug: string}>>
     */
    public function getRolesForUsers(array $userUuids): array
    {
        $out = [];
        if ($userUuids === []) {
            return $out;
        }
        $now = $this->db->getDriver()->formatDateTime();
        $rows = $this->db->table('user_roles')
            ->select([
                'user_roles.user_uuid AS user_uuid',
                'roles.uuid AS role_uuid',
                'roles.name AS role_name',
                'roles.slug AS role_slug',
            ])
            ->join('roles', 'roles.uuid', '=', 'user_roles.role_uuid')
            ->whereIn('user_roles.user_uuid', $userUuids)
            ->whereNull('roles.deleted_at')
            ->where(function ($q) use ($now) {
                $q->where('user_roles.expires_at', '>=', $now)
                  ->orWhereNull('user_roles.expires_at');
            })
            ->get();
        foreach ($rows as $r) {
            $out[(string) $r['user_uuid']][] = [
                'uuid' => (string) $r['role_uuid'],
                'name' => (string) $r['role_name'],
                'slug' => (string) $r['role_slug'],
            ];
        }
        return $out;
    }

    /**
     * @return list<UserRole>
     */
    public function findByRole(string $roleUuid): array
    {
        $results = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['role_uuid' => $roleUuid])
            ->orderBy(['created_at' => 'DESC'])
            ->get();

        return array_map(fn($row) => new UserRole($row), $results);
    }

    public function findUserRole(string $userUuid, string $roleUuid): ?UserRole
    {
        $result = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where([
                'user_uuid' => $userUuid,
                'role_uuid' => $roleUuid
            ])
            ->limit(1)
            ->get();

        return $result ? new UserRole($result[0]) : null;
    }

    /**
     * @param array<string, mixed> $scope
     */
    public function hasUserRole(string $userUuid, string $roleUuid, array $scope = []): bool
    {
        $query = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where([
                'user_uuid' => $userUuid,
                'role_uuid' => $roleUuid
            ]);

        // Check if role is still active (not expired)
        $currentTime = $this->db->getDriver()->formatDateTime();
        $query->where(function ($q) use ($currentTime) {
            $q->where('expires_at', '>=', $currentTime)
              ->orWhereNull('expires_at');
        });

        $results = $query->get();

        if (empty($results)) {
            return false;
        }

        // If we have scope requirements, check scope matching
        if (!empty($scope)) {
            foreach ($results as $row) {
                $userRole = new UserRole($row);
                if ($userRole->matchesScope($scope)) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }

    /**
     * @param array<string, mixed> $scope
     * @return list<UserRole>
     */
    public function getUserRoles(string $userUuid, array $scope = []): array
    {
        // Only get active (non-expired) roles
        $currentTime = $this->db->getDriver()->formatDateTime();

        $query = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where('user_uuid', '=', $userUuid)
            ->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });

        $results = $query->get();
        $userRoles = array_map(fn($row) => new UserRole($row), $results);

        // Filter by scope if provided
        if (!empty($scope)) {
            $userRoles = array_filter($userRoles, function ($role) use ($scope) {
                return $role->matchesScope($scope);
            });
        }

        $userRoles = array_values($userRoles);

        return $userRoles;
    }

    /**
     * @param array<string, mixed> $scope
     * @return list<string>
     */
    public function getUserRoleUuids(string $userUuid, array $scope = []): array
    {
        $userRoles = $this->getUserRoles($userUuid, $scope);
        return array_map(fn($role) => $role->getRoleUuid(), $userRoles);
    }

    /**
     * Active (non-expired) role slugs for a principal, via a single user_roles -> roles join
     * (no N+1 — getUserRoles() returns UserRole models carrying only role_uuid). The user uuid is
     * an external principal id (no FK); this is what IdentityClaimsProvider folds into claims.
     *
     * @return list<string>
     */
    public function roleSlugsForUser(string $userUuid): array
    {
        // QueryBuilder::where() only normalizes the 2-arg form when the 2nd arg is NOT a string,
        // so a UUID string must use the explicit 3-arg operator form.
        $currentTime = $this->db->getDriver()->formatDateTime();

        $rows = $this->db->table('user_roles')
            ->join('roles', 'user_roles.role_uuid', '=', 'roles.uuid')
            ->where('user_roles.user_uuid', '=', $userUuid)
            ->where(function ($q) use ($currentTime) {
                $q->where('user_roles.expires_at', '>=', $currentTime)
                  ->orWhereNull('user_roles.expires_at');
            })
            ->select(['roles.slug'])
            ->get();

        return array_values(array_column($rows, 'slug'));
    }

    /**
     * @param array<string, mixed> $options
     */
    public function assignRole(string $userUuid, string $roleUuid, array $options = []): ?UserRole
    {
        $scope = $options['scope'] ?? [];

        // Check if assignment already exists
        if ($this->hasUserRole($userUuid, $roleUuid, $scope)) {
            return $this->findMatchingUserRole($userUuid, $roleUuid, $scope);
        }

        $data = [
            'user_uuid' => $userUuid,
            'role_uuid' => $roleUuid,
            'granted_by' => $options['granted_by'] ?? null,
            'expires_at' => $options['expires_at'] ?? null
        ];

        if (isset($options['scope'])) {
            $data['scope'] = json_encode($options['scope']);
        }

        return $this->createUserRole($data);
    }

    /**
     * @param array<string, mixed> $scope
     */
    private function findMatchingUserRole(string $userUuid, string $roleUuid, array $scope = []): ?UserRole
    {
        foreach ($this->findByUser($userUuid, ['role_uuid' => $roleUuid, 'active_only' => true]) as $userRole) {
            if ($userRole->matchesScope($scope)) {
                return $userRole;
            }
        }

        return null;
    }

    public function revokeRole(string $userUuid, string $roleUuid): bool
    {
        return (bool) $this->db->table($this->table)->where([
            'user_uuid' => $userUuid,
            'role_uuid' => $roleUuid
        ])->delete();
    }

    public function revokeAllUserRoles(string $userUuid): bool
    {
        return (bool) $this->db->table($this->table)->where(['user_uuid' => $userUuid])->delete();
    }

    /**
     * @return list<UserRole>
     */
    public function findExpiredRoles(): array
    {
        $currentTime = $this->db->getDriver()->formatDateTime();
        $results = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', $currentTime)
            ->orderBy(['expires_at' => 'ASC'])
            ->get();

        return array_map(fn($row) => new UserRole($row), $results);
    }

    public function cleanupExpiredRoles(): int
    {
        $currentTime = $this->db->getDriver()->formatDateTime();

        $count = $this->db->table($this->table)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', $currentTime)
            ->count();

        if ($count > 0) {
            // Get expired role UUIDs and delete them individually
            $deleteQuery = $this->db->table($this->table)
                ->select(['uuid'])
                ->whereNotNull('expires_at')
                ->where('expires_at', '<', $currentTime);

            $expiredUuids = array_column($deleteQuery->get(), 'uuid');
            if (!empty($expiredUuids)) {
                $this->bulkDelete($expiredUuids);
            }
        }

        return $count;
    }

    /**
     * @return list<UserRole>
     */
    public function findByGrantedBy(string $grantedByUuid): array
    {
        $results = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['granted_by' => $grantedByUuid])
            ->orderBy(['created_at' => 'DESC'])
            ->get();

        return array_map(fn($row) => new UserRole($row), $results);
    }

    /**
     * @param array<string, mixed> $filters
     * @return list<string>
     */
    public function getUsersWithRole(string $roleUuid, array $filters = []): array
    {
        $query = $this->db->table($this->table)
            ->select(['user_uuid'])
            ->distinct()
            ->where(['role_uuid' => $roleUuid]);

        if (isset($filters['active_only']) && $filters['active_only']) {
            $currentTime = $this->db->getDriver()->formatDateTime();
            $query->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });
        }

        $results = $query->get();
        return array_column($results, 'user_uuid');
    }

    /**
     * @param array<string, mixed> $filters
     */
    public function countUserRoles(string $userUuid, array $filters = []): int
    {
        $query = $this->db->table($this->table)
            ->where(['user_uuid' => $userUuid]);

        if (isset($filters['active_only']) && $filters['active_only']) {
            $currentTime = $this->db->getDriver()->formatDateTime();
            $query->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });
        }

        return $query->count();
    }

    /**
     * @param array<string, mixed> $filters
     * @return list<UserRole>
     */
    public function findRoleAssignments(array $filters = []): array
    {
        $query = $this->db->table($this->table)->select($this->defaultFields);

        if (isset($filters['role_uuid'])) {
            $query->where(['role_uuid' => $filters['role_uuid']]);
        }

        if (isset($filters['granted_by'])) {
            $query->where(['granted_by' => $filters['granted_by']]);
        }

        if (isset($filters['active_only']) && $filters['active_only']) {
            $currentTime = $this->db->getDriver()->formatDateTime();
            $query->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });
        }

        $query->orderBy(['created_at' => 'DESC']);

        $results = $query->get();
        return array_map(fn($row) => new UserRole($row), $results);
    }

    /**
     * Get paginated user role history
     *
     * @param string $userUuid User UUID to get history for
     * @param array<string, mixed> $filters Additional filters
     * @param int $page Page number (1-based)
     * @param int $perPage Number of items per page
     * @return array<string, mixed> Paginated results with metadata
     */
    public function getUserRoleHistoryPaginated(
        string $userUuid,
        array $filters = [],
        int $page = 1,
        int $perPage = 25
    ): array {
        // Start with base query
        $query = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['user_uuid' => $userUuid]);

        // Apply filters
        if (isset($filters['exclude_deleted']) && $filters['exclude_deleted']) {
            $query->whereNull('deleted_at');
        }

        if (isset($filters['role_uuid'])) {
            $query->where(['role_uuid' => $filters['role_uuid']]);
        }

        if (isset($filters['granted_by'])) {
            $query->where(['granted_by' => $filters['granted_by']]);
        }

        // Store active_only filter for post-processing
        $filterActiveOnly = isset($filters['active_only']) && $filters['active_only'];

        // Order by most recent first
        $query->orderBy(['created_at' => 'DESC']);

        // Use QueryBuilder's pagination method
        $result = $query->paginate($page, $perPage);

        // Transform data to include role information
        $transformedData = [];
        $currentTime = $this->db->getDriver()->formatDateTime();

        // First pass: collect valid user roles and their role UUIDs
        $validUserRoles = [];
        $roleUuids = [];
        foreach ($result['data'] as $row) {
            $userRole = new UserRole($row);

            // Apply active_only filter if needed
            if ($filterActiveOnly) {
                $expiresAt = $userRole->getExpiresAt();
                if ($expiresAt !== null && $expiresAt < $currentTime) {
                    continue; // Skip expired roles
                }
            }

            $validUserRoles[] = ['row' => $row, 'userRole' => $userRole];
            $roleUuids[] = $row['role_uuid'];
        }

        // Fetch all role data in a single query to avoid N+1 problem
        $rolesMap = [];
        if (!empty($roleUuids)) {
            $roleUuids = array_unique($roleUuids); // Remove duplicates
            $roles = $this->db->table('roles')
                ->select(['uuid', 'name', 'slug', 'description'])
                ->whereIn('uuid', $roleUuids)
                ->get();

            // Create a map for quick lookup
            foreach ($roles as $role) {
                $rolesMap[$role['uuid']] = $role;
            }
        }

        // Second pass: build final transformed data with role information
        foreach ($validUserRoles as $item) {
            $row = $item['row'];
            $userRole = $item['userRole'];
            $roleData = $rolesMap[$row['role_uuid']] ?? null;

            $transformedData[] = [
                'uuid' => $userRole->getUuid(),
                'user_uuid' => $userRole->getUserUuid(),
                'role_uuid' => $userRole->getRoleUuid(),
                'scope' => $userRole->getScope(),
                'granted_by' => $userRole->getGrantedBy(),
                'expires_at' => $userRole->getExpiresAt(),
                'created_at' => $userRole->getCreatedAt(),
                'deleted_at' => $row['deleted_at'] ?? null,
                'role' => $roleData ? [
                    'name' => $roleData['name'],
                    'slug' => $roleData['slug'],
                    'description' => $roleData['description']
                ] : null
            ];
        }

        // Extract pagination metadata from the flat result structure
        $pagination = $result;
        unset($pagination['data']);

        return [
            'data' => $transformedData,
            'current_page' => $result['current_page'],
            'per_page' => $result['per_page'],
            'total' => $result['total'],
            'last_page' => $result['last_page'],
            'has_more' => $result['has_more'],
            'from' => $result['from'],
            'to' => $result['to']
        ];
    }

    /**
     * Get user roles for multiple users efficiently
     *
     * @param list<string> $userUuids Array of user UUIDs
     * @param array<string, mixed> $scope Optional scope filter
     * @return list<UserRole> Array of UserRole objects
     */
    public function getBulkUserRoles(array $userUuids, array $scope = []): array
    {
        if (empty($userUuids)) {
            return [];
        }

        $query = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->whereIn('user_uuid', $userUuids);

        // Apply scope filters if provided
        if (!empty($scope)) {
            $query->where(['scope' => $scope]);
        }

        $results = $query->get();
        $userRoles = [];

        foreach ($results as $row) {
            $userRoles[] = new UserRole($row);
        }

        return $userRoles;
    }
}
