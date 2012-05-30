module SsoSap
  class InfoUnit
    attr :id
    attr :name
    attr :value
    attr :binary

    def initialize(id, name, value, binary)
      @id, @name, @value, @binary = id, name, value, binary
    end
  end
end
